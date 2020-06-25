#include "regexp-executor.hpp"

#include <string>
#include <iostream>

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

v8::ArrayBuffer::Allocator *_allocator = nullptr;
v8::Isolate *isolate = nullptr;
v8::internal::Isolate *i_isolate = nullptr;
std::unique_ptr<v8::Platform> platform = nullptr;
v8::Global<v8::Context> context;

/**
 * Initialization requires "argv[0]" -- the program name;
 * since we're faking it, this is the program name
 */
std::string fake_prog_name = "regulator";


static const char *MY_ZONE_NAME = "MY_ZONE";

V8RegExp::V8RegExp()
{
    this->regexp = v8::internal::Handle<v8::internal::JSRegExp>::null();
}


V8RegExpResult::V8RegExpResult()
{
    this->match = v8::internal::Handle<v8::internal::RegExpMatchInfo>::null();
    this->match_success = false;
    this->opcount = 0;
    this->coverage_tracker = nullptr;
}


V8RegExpResult::~V8RegExpResult()
{
    if (this->coverage_tracker != nullptr)
    {
        delete this->coverage_tracker;
    }
}


v8::Isolate *Initialize()
{
    if (_initialized)
    {
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

    _allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();

    v8::Isolate::CreateParams isolateCreateParams;
    isolateCreateParams.array_buffer_allocator = _allocator;
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


Result Compile(const char *pattern, const char *flags, V8RegExp *out)
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
        return Result::kNotValidUtf8;
    }

    // TODO make flags useful
    v8::internal::JSRegExp::Flags parsed_flags = v8::internal::JSRegExp::kNone;

    v8::internal::MaybeHandle<v8::internal::JSRegExp> maybe_h_regexp = (
            v8::internal::JSRegExp::New(i_isolate, h_pattern, parsed_flags)
    );

    v8::internal::Handle<v8::internal::JSRegExp> h_regexp;
    if (!maybe_h_regexp.ToHandle(&h_regexp))
    {
        return Result::kCouldNotCompile;
    }

    // Force pre-compilation of the regular expression. In the irregexp
    // matching system, compilation is lazy: it will only occur on-demand
    // when a regexp is executed against a string (ie my_pat.test('foobar')).
    // Another interesting issue is that some irregexp compiler optimizations
    // depend upon the content of that first string. Moreover, the first
    // string will determine whether latin1 or utf8 compilation is performed.

    // This encodes the snowman emoji as a string, which we use to force utf-8,
    // compilation otherwise the regexp will compile to latin1
    v8::internal::Handle<v8::internal::String> subject = (
        i_isolate->factory()
                ->NewStringFromUtf8(
                    v8::internal::CStrVector("\xE2\x98\x83")
                )
    ).ToHandleChecked();

    int capture_count = h_regexp->CaptureCount();
    v8::internal::Handle<v8::internal::RegExpMatchInfo> match_info =
        v8::internal::RegExpMatchInfo::New(i_isolate, capture_count);

    v8::internal::Handle<v8::internal::Object> o2 = v8::internal::RegExp::Exec(
        i_isolate, h_regexp, subject, 0, match_info).ToHandleChecked();

    out->regexp = h_regexp;

    return Result::kSuccess;
}


Result Exec(V8RegExp *regexp, char *subject, size_t subject_len, V8RegExpResult *out)
{
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

        v8::internal::MaybeHandle<v8::internal::String> maybe_h_subject = i_isolate->factory()
            ->NewStringFromUtf8(
                v8::internal::VectorOf<char>(subject, subject_len + 1)
            );

        v8::internal::Handle<v8::internal::String> h_subject;
        if (!maybe_h_subject.ToHandle(&h_subject))
        {
            return Result::kNotValidUtf8;
        }

        int capture_count = regexp->regexp->CaptureCount();
        v8::internal::Handle<v8::internal::RegExpMatchInfo> match_info = i_isolate->factory()->NewRegExpMatchInfo();

        v8::internal::regexp_exec_cost = 0;
        v8::internal::Handle<v8::internal::Object> o2 = v8::internal::RegExp::Exec(
                i_isolate, regexp->regexp, h_subject, 0, match_info).ToHandleChecked();

        if (i_isolate->has_pending_exception())
        {
            std::cerr << "Pending exception!!!" << std::endl;
        }

        // out->match = match_info;
        out->opcount = v8::internal::regexp_exec_cost;
        out->match_success = !(o2->IsNull());
        out->coverage_tracker = v8::internal::coverage_tracker;

        uint64_t pumps = 0;
        while (v8::platform::PumpMessageLoop(platform.get(), isolate))
        {
            pumps++;
        }
        if (pumps > 1)
        {
            // std::cout << "unusual number of pumps: " << pumps << std::endl;
        }
    }

    return Result::kSuccess;
}

}
}