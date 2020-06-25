#include <iostream>

#include "v8.h"
#include "src/objects/regexp-match-info.h"
#include "regexp-executor.hpp"

#include "catch.hpp"

namespace e = regulator::executor;

TEST_CASE( "Match info should encompass the whole match in 0th and 1st register" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();


    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("qui[c]k", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result;
    e::Result exec_result_status = e::Exec(&regexp, "the quick brown fox", 19, &exec_result);

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == true );
    
    v8::internal::Handle<v8::internal::RegExpMatchInfo> h_match = exec_result.match.ToHandleChecked();

    REQUIRE( h_match->Capture(0) == 4 );
    REQUIRE( h_match->Capture(1) == 9 );
}

TEST_CASE( "Match info should contain capture group" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();


    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("qui[c]k (br.wn)", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result;
    e::Result exec_result_status = e::Exec(&regexp, "the quick brown fox", 19, &exec_result);
    

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == true );
    
    v8::internal::Handle<v8::internal::RegExpMatchInfo> h_match = exec_result.match.ToHandleChecked();

    REQUIRE( h_match->NumberOfCaptureRegisters() == 4 );
    REQUIRE( h_match->Capture(0) == 4 );
    REQUIRE( h_match->Capture(1) == 15 );
    REQUIRE( h_match->Capture(2) == 10 );
    REQUIRE( h_match->Capture(3) == 15 );
}
