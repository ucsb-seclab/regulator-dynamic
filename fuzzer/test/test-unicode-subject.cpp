#include <iostream>

#include "v8.h"
#include "regexp-executor.hpp"

#include "catch.hpp"

namespace e = regulator::executor;

TEST_CASE( "simple unicode subject string" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();


    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("fo.obar", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result;
    char subject[] = {
        'f',
        'o',
        '\xc3', '\x83', // unicode LATIN CAPITAL LETTER A WITH TILDE
        'o',
        'b',
        'a',
        'r',
    };
    e::Result exec_result_status = e::Exec(&regexp, subject, sizeof(subject), &exec_result);
    
    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == true );
}
