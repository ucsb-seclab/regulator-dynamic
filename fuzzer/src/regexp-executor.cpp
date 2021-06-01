#include "regexp-executor.hpp"

#include <string>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>

#include "v8.h"
#include "src/execution/isolate.h"
#include "src/objects/objects.h"
#include "src/objects/js-regexp.h"
#include "src/objects/js-regexp-inl.h"
#include "src/regexp/regexp-bytecode-generator.h"
#include "src/regexp/regexp.h"
#include "src/regexp/regexp-interpreter.h"
#include "src/objects/fixed-array.h"
#include "src/objects/fixed-array-inl.h"
#include "include/libplatform/libplatform.h"

namespace regulator
{
namespace executor
{

bool _initialized = false;

thread_local v8::Isolate *isolate = nullptr;
thread_local v8::internal::Isolate *i_isolate = nullptr;
std::unique_ptr<v8::Platform> platform = nullptr;
thread_local v8::Global<v8::Context> context;

/**
 * Initialization requires "argv[0]" -- the program name;
 * since we're faking it, this is the program name
 */
std::string fake_prog_name = "regulator";

/**
 * Sentinel value for std::thread::id to represent null
 */
static const std::thread::id kNullThreadId;

static const char *MY_ZONE_NAME = "MY_ZONE";

V8RegExp::V8RegExp()
{
    this->regexp = v8::internal::Handle<v8::internal::JSRegExp>::null();
}


V8RegExpResult::V8RegExpResult()
{
    this->match_success = false;
    this->coverage_tracker = std::make_unique<regulator::fuzz::CoverageTracker>(0);
}

V8RegExpResult::V8RegExpResult(uint32_t string_length)
{
    this->match_success = false;
    this->coverage_tracker = std::make_unique<regulator::fuzz::CoverageTracker>(string_length);
}

V8RegExpResult::~V8RegExpResult()
{
}


v8::Isolate *Initialize()
{
    if (_initialized)
    {
        if (isolate == nullptr)
        {
            // this is a new thread that needs its own isolate
            v8::ArrayBuffer::Allocator *allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
            v8::Isolate::CreateParams isolateCreateParams;
            isolateCreateParams.array_buffer_allocator = allocator;
            isolate = v8::Isolate::New(isolateCreateParams);
            isolate->Enter();

            {
                // this funky business creates a Context which escapes local scope
                // seen in v8 file: fuzzer-support.cc
                v8::Isolate::Scope isolate_scope(isolate);
                v8::HandleScope handle_scope(isolate);
                context.Reset(isolate, v8::Context::New(isolate));
            }

            i_isolate = reinterpret_cast<v8::internal::Isolate*>(isolate);
        }
        return isolate;
    }
    _initialized = true;

    v8::internal::FLAG_expose_gc = true;

    v8::V8::InitializeICUDefaultLocation(fake_prog_name.c_str());
    platform = v8::platform::NewDefaultPlatform();
    v8::V8::InitializePlatform(platform.get());

    // note: we need to set the flags, so let's just make a fake argc and argv
    {
        char *fake_argv[] = {(char *)fake_prog_name.c_str(), NULL};
        int fake_argc = 1;
        v8::internal::FlagList::SetFlagsFromCommandLine(&fake_argc, fake_argv, false);
    }

    v8::V8::Initialize();
    v8::V8::InitializeExternalStartupData(fake_prog_name.c_str());

    v8::ArrayBuffer::Allocator *allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();

    v8::Isolate::CreateParams isolateCreateParams;
    isolateCreateParams.array_buffer_allocator = allocator;
    isolate = v8::Isolate::New(isolateCreateParams);
    isolate->Enter();
    i_isolate = reinterpret_cast<v8::internal::Isolate*>(isolate);

    {
        // this funky business creates a Context which escapes local scope
        // seen in v8 file: fuzzer-support.cc
        v8::Isolate::Scope isolate_scope(isolate);
        v8::HandleScope handle_scope(isolate);
        context.Reset(isolate, v8::Context::New(isolate));
    }

    // Oddly, if you only set the first flag it will still attempt to
    // tier-up compile (native compile) the bytecode, then fail a debug
    // check. So, set BOTH here to ensure interpretation.
    v8::internal::FLAG_regexp_interpret_all = true;
    v8::internal::FLAG_regexp_tier_up = false;

    return isolate;
}


Result Compile(const char *pattern, const char *flags, V8RegExp *out, uint16_t n_threads)
{
    v8::internal::MaybeHandle<v8::internal::String> maybe_h_pattern = (
        i_isolate->factory()
                 ->NewStringFromUtf8(
                     v8::internal::CStrVector(pattern)
                )
    );

    v8::internal::Handle<v8::internal::String> h_pattern;
    if (!maybe_h_pattern.ToHandle(&h_pattern))
    {
        return Result::kNotValidString;
    }

    v8::internal::JSRegExp::Flags parsed_flags = v8::internal::JSRegExp::kNone;

    for (; *flags != '\0'; flags++)
    {
        char flag = *flags;
        switch (flag)
        {
        case 'G':
        case 'g':
            parsed_flags |= v8::internal::JSRegExp::kGlobal;
            break;
        case 'I':
        case 'i':
            parsed_flags |= v8::internal::JSRegExp::kIgnoreCase;
            break;
        case 'M':
        case 'm':
            parsed_flags |= v8::internal::JSRegExp::kMultiline;
            break;
        case 'S':
        case 's':
            parsed_flags |= v8::internal::JSRegExp::kDotAll;
            break;
        case 'U':
        case 'u':
            parsed_flags |= v8::internal::JSRegExp::kUnicode;
            break;
        case 'Y':
        case 'y':
            // Ignore this -- for fuzzing we only want to run starting
            // from position 0; sticky would make for weird re-running
            // behavior.
            // parsed_flags |= v8::internal::JSRegExp::kSticky;
            break;
        default:
            return Result::kCouldNotCompile;
        }
    }

    v8::internal::MaybeHandle<v8::internal::JSRegExp> maybe_h_regexp = (
            v8::internal::JSRegExp::New(i_isolate, h_pattern, parsed_flags)
    );

    v8::internal::Handle<v8::internal::JSRegExp> h_regexp;
    if (!maybe_h_regexp.ToHandle(&h_regexp))
    {
        return Result::kCouldNotCompile;
    }

    // Force (partial) pre-compilation of the regular expression. In the irregexp
    // matching system, compilation is lazy: it will only occur on-demand
    // when a regexp is executed against a string (ie my_pat.test('foobar')).
    // Another interesting issue is that some irregexp compiler optimizations
    // depend upon the content of that first string.
    v8::internal::Handle<v8::internal::String> subject = (
        i_isolate->factory()
                ->NewStringFromUtf8(
                    v8::internal::CStrVector("\xE2\x98\x83")
                )
    ).ToHandleChecked();

    const int capture_count = h_regexp->CaptureCount();
    v8::internal::Handle<v8::internal::RegExpMatchInfo> match_info =
        v8::internal::RegExpMatchInfo::New(i_isolate, capture_count);

    v8::internal::Handle<v8::internal::Object> o2 = v8::internal::RegExp::Exec(
        i_isolate, h_regexp, subject, 0, match_info).ToHandleChecked();

    if (h_regexp->TypeTag() != v8::internal::JSRegExp::IRREGEXP)
    {
        return Result::kCouldNotCompile;
    }

    out->regexp = h_regexp;

    // start allocating space for match infos (while, presumably, on main thread ourselves)
    std::unique_lock<std::mutex> my_lock(out->match_infos_mutex);
    out->match_infos = nullptr;
    // note we'll make one extra for the main thread
    for (size_t i=0; i < n_threads + 1; i++)
    {
        struct ThreadLocalV8RegExpMatchInfo *mi = new struct ThreadLocalV8RegExpMatchInfo;
        mi->match_info = v8::internal::RegExpMatchInfo::New(i_isolate, capture_count);
        mi->next = out->match_infos;
        mi->owning_thread = kNullThreadId;
        out->match_infos = mi;
    }

    return Result::kSuccess;
}


/**
 * Helpers to deal with the constructing a string w/ either 1 or 2-byte (see also overload below)
 */
inline v8::internal::MaybeHandle<v8::internal::String>
    construct_string(const uint8_t *subject, size_t subject_len, v8::internal::Isolate *i_isolate)
{
    return i_isolate->factory()
            ->NewStringFromOneByte(
                v8::internal::VectorOf<const uint8_t>(subject, subject_len)
            );
}


inline v8::internal::MaybeHandle<v8::internal::String>
    construct_string(const uint16_t *subject, size_t subject_len, v8::internal::Isolate *i_isolate)
{
    return i_isolate->factory()
            ->NewStringFromTwoByte(
                v8::internal::VectorOf<const uint16_t>(subject, subject_len)
            );
}


template<typename Char>
Result Exec(
    V8RegExp *regexp,
    const Char *subject,
    size_t subject_len,
    V8RegExpResult &out,
    int32_t max_total,
#if defined REG_COUNT_PATHLENGTH
    uint64_t max_path,
#endif
    EnforceRepresentation rep)
{
    // Following set-up seen at v8 file fuzzer/regexp.cc
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> local_context = v8::Local<v8::Context>::New(isolate, context);
    v8::Context::Scope context_scope(local_context);
    v8::TryCatch try_catch(isolate);

    if (i_isolate->has_pending_exception())
    {
        std::cerr << "Pending exception???" << std::endl;
    }

    v8::internal::MaybeHandle<v8::internal::String> maybe_h_subject = construct_string(
        subject,
        subject_len,
        i_isolate
    );

    v8::internal::Handle<v8::internal::String> h_subject;
    if (!maybe_h_subject.ToHandle(&h_subject))
    {
        return Result::kNotValidString;
    }

    if (rep != kAnyRepresentation)
    {
        if (rep == kOnlyOneByte && !h_subject->IsOneByteRepresentation(i_isolate))
        {
            return Result::kBadStrRepresentation;
        }
        else if (rep == kOnlyTwoByte && h_subject->IsOneByteRepresentation(i_isolate))
        {
            return Result::kBadStrRepresentation;
        }
    }

    out.rep_used = kRepOneByte;
    if (h_subject->IsTwoByteRepresentation())
    {
        out.rep_used = kRepTwoByte;
    }


    v8::internal::Handle<v8::internal::RegExpMatchInfo> match_info(nullptr);
    for (struct ThreadLocalV8RegExpMatchInfo *curr = regexp->match_infos;
         curr != nullptr && match_info.is_null();
         curr = curr->next)
    {
        if (curr->owning_thread == kNullThreadId)
        {
            // nobody owns this, claim it for ourselves I guess
            std::unique_lock<std::mutex> lock(regexp->match_infos_mutex);

            // double-check to avoid a data race
            if (curr->owning_thread == kNullThreadId)
            {
                curr->owning_thread = std::this_thread::get_id();
            }
            else
            {
                // if we lost the race then start the list iteration over again
                curr = regexp->match_infos;
            }
        }
        if (curr->owning_thread == std::this_thread::get_id())
        {
            match_info = curr->match_info;
        }
    }
    
    if (match_info.is_null())
    {
        std::cerr << "ERROR: bad match_info?" << std::endl;
        return Result::kCouldNotCompile;
    }

    out.coverage_tracker->Clear();
    v8::internal::MaybeHandle<v8::internal::Object> o2 = v8::internal::RegExp::Exec(
        i_isolate,
        regexp->regexp,
        h_subject,
        0,
        match_info,
        max_total,
#if defined REG_COUNT_PATHLENGTH
        max_path,
#endif
        out.coverage_tracker.get()
    );

    if (o2.is_null())
    {
        out.match_success = false;
    }
    else
    {
        out.match_success = !(o2.ToHandleChecked()->IsNull());
    }

    if (i_isolate->has_pending_exception())
    {
        std::cerr << "Pending exception!!!" << std::endl;
    }

    out.coverage_tracker->Bucketize();

    // NOTE: we /could/ do this if we coordinated threads correctly (Pump... requires
    // a specific thread to run in). HOWEVER it's only useful for running the GC, which
    // we don't care about.
    // uint64_t pumps = 0;
    // while (v8::platform::PumpMessageLoop(platform.get(), isolate))
    // {
    //     pumps++;
    // }
    // if (pumps > 2)
    // {
    //     std::cout << "unusual number of pumps: " << pumps << std::endl;
    // }

    // check if we violated max total
    if (max_total >= 0 && out.coverage_tracker->Total() >= max_total)
    {
        return Result::kViolateMaxTotal;
    }
    return Result::kSuccess;
}

template
Result Exec<uint8_t>(
    V8RegExp *regexp,
    const uint8_t *subject,
    size_t subject_len,
    V8RegExpResult &out,
    int32_t max_total,
#if defined REG_COUNT_PATHLENGTH
    uint64_t max_path,
#endif
    EnforceRepresentation rep);

template
Result Exec<uint16_t>(
    V8RegExp *regexp,
    const uint16_t *subject,
    size_t subject_len,
    V8RegExpResult &out,
    int32_t max_total,
#if defined REG_COUNT_PATHLENGTH
    uint64_t max_path,
#endif
    EnforceRepresentation rep);

}
}