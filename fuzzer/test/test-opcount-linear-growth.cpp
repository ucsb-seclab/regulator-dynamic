#include <iostream>

#include "v8.h"
#include "regexp-executor.hpp"

#include "catch.hpp"

namespace e = regulator::executor;

TEST_CASE( "opcount should grow as a linearly-bounded function for simple case 1" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();


    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("foo+", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    // idea: the function `f: int -> int` maps string length
    // to an upper bound on the opcount; Here, I use the following
    // observations taken from the regexp 'foo+' and subject 'foo...ooo'
    // to set the linear function `f`:
    //
    // f(1) = 18
    // f(2) = 21
    // f(3) = 24
    // f(4) = 27
    // f(5) = 30
    // f(6) = 33
    // f(7) = 36
    // f(8) = 39
    // f(9) = 42
    //
    // So, I infer f(x) = 15 + 3x, but below will use f'(x) = f(x) + 10
    // to allow for a small margin


    e::V8RegExpResult exec_result;

    for (size_t i = 1; i < 100; i++)
    {
        // construct the subject string with `i+1` 'o' chars
        std::string subject = "fo";
        for (size_t j = 0; j < i; j++)
        {
            subject.append("o");
        }

        e::Result exec_result_status = e::Exec<uint8_t>(
            &regexp,
            reinterpret_cast<const uint8_t *>(subject.c_str()),
            2 + i,
            exec_result
        );

        uint64_t expected_max = 15 + (3 * i) + 10;
        
        REQUIRE( exec_result.coverage_tracker->Total() < expected_max );
    }
}
