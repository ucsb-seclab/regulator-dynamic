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
}


v8::Isolate *Initialize()
{
    if (_initialized)
    {
        return isolate;
    }
    _initialized = true;

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

    // Oddly, if you only set the first flag it will still attempt to
    // tier-up compile (native compile) the bytecode, then fail a debug
    // check. So, set BOTH here to ensure interpretation.
    v8::internal::FLAG_regexp_interpret_all = true;
    v8::internal::FLAG_regexp_tier_up = false;

    std::cout << "finishing init" << std::endl;
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
    v8::internal::MaybeHandle<v8::internal::String> maybe_h_subject = i_isolate->factory()
        ->NewStringFromUtf8(
            v8::internal::VectorOf<char>(subject, subject_len + 1)
        );

    v8::internal::Handle<v8::internal::String> h_subject;
    if (!maybe_h_subject.ToHandle(&h_subject))
    {
        return Result::kNotValidUtf8;
    }

    v8::internal::Handle<v8::internal::JSRegExp> h_regexp = regexp->regexp;
    int capture_count = h_regexp->CaptureCount();

    v8::internal::Handle<v8::internal::RegExpMatchInfo> match_info =
            v8::internal::RegExpMatchInfo::New(i_isolate, capture_count);

    v8::internal::regexp_exec_cost = 0;
    v8::internal::Handle<v8::internal::Object> o2 = v8::internal::RegExp::Exec(
            i_isolate, regexp->regexp, h_subject, 0, match_info).ToHandleChecked();

    out->match = match_info;
    out->opcount = v8::internal::regexp_exec_cost;
    out->match_success = !(o2->IsNull());

    return Result::kSuccess;
}

}
}