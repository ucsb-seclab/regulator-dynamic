#include <iostream>

#include "v8.h"
#include "regexp-executor.hpp"

#include "catch.hpp"

namespace e = regulator::executor;

TEST_CASE( "Should be able to match, simple case" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();


    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("fo[o]", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result;
    e::Result exec_result_status = e::Exec(&regexp, "foo", 3, &exec_result);
    
    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == true );
}

TEST_CASE( "Should be able to no-match, simple case" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("fo[o]", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result;
    e::Result exec_result_status = e::Exec(&regexp, "bar", 3, &exec_result);

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == false );
}

TEST_CASE( "Should have non-zero opcount" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("fo[o]", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result;
    e::Result exec_result_status = e::Exec(&regexp, "bar", 3, &exec_result);

    REQUIRE( exec_result.opcount > 0 );
}

TEST_CASE( "opcount should increase as match generally increases" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("foo+", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result;
    e::Result exec_result_status = e::Exec(&regexp, "foo", 3, &exec_result);

    REQUIRE( exec_result_status == e::kSuccess );

    uint64_t first_match_opcount = exec_result.opcount;

    exec_result_status = e::Exec(&regexp, "foooo", 5, &exec_result);

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.opcount > first_match_opcount );
}
