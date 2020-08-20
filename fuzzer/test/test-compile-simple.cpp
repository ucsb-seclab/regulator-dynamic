#include "v8.h"
#include "regexp-executor.hpp"

#include "catch.hpp"


TEST_CASE( "Should not compile atoms" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    regulator::executor::V8RegExp regexp;
    const char pat[] = "fooo";
    regulator::executor::Result result = regulator::executor::Compile(pat, "", &regexp);

    REQUIRE( result == regulator::executor::Result::kCouldNotCompile );
}

TEST_CASE( "Should be able to compile simple case" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();


    regulator::executor::V8RegExp regexp;
    const char pat[] = "fooo.";
    regulator::executor::Result result = regulator::executor::Compile(pat, "", &regexp);

    REQUIRE( result == regulator::executor::Result::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );
}


TEST_CASE( "Should be able to compile wildcard" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    regulator::executor::V8RegExp regexp;
    regulator::executor::Result result = regulator::executor::Compile("a.b", "", &regexp);

    REQUIRE( result == regulator::executor::Result::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );
}


TEST_CASE( "Should be able to compile repetitions" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    regulator::executor::V8RegExp regexp;
    regulator::executor::Result result = regulator::executor::Compile("ab+c", "", &regexp);

    REQUIRE( result == regulator::executor::Result::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );
}
