#include <iostream>

#include "v8.h"
#include "regexp-executor.hpp"

#include "catch.hpp"

namespace e = regulator::executor;

TEST_CASE( "opcount should grow as a quadratically-bounded function for simple case 1" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("^\\d+1\\d+2", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    // idea: the function `f: int -> int` maps string length
    // to an upper bound on the opcount; Here, I use the following
    // observations of observed opcounts from the regexp '^\d+1\d+2'
    // and subject string '11111...11113' to set the quadratic
    // function `f`:
    //
    // f(1) = 21
    // f(2) = 43
    // f(3) = 72
    // f(4) = 108
    // f(5) = 151
    // f(6) = 201
    // f(7) = 258
    // f(8) = 322
    // f(9) = 393
    //
    // So, I infer f(x) = 3.5 x ^ 2 + 11.5 x + 6 , but below will use f'(x) = f(x) + 10
    // to allow for a small margin.

    e::V8RegExpResult exec_result;
    for (size_t i = 1; i < 100; i++)
    {
        // construct the subject string with `i+1` 'o' chars
        std::string subject = "";
        for (size_t j = 0; j < i; j++)
        {
            subject.append("1");
        }
        subject.append("3");

        e::Result exec_result_status = e::Exec<uint8_t>(
            &regexp,
            reinterpret_cast<const uint8_t *>(subject.c_str()),
            1 + i,
            exec_result
        );

        uint64_t opcount_max = ((7 * (i * i)) + (23 * i)) / 2 + 6 + 10;
        
        REQUIRE( exec_result.coverage_tracker->Total() < (opcount_max + 10) );
    }
}
