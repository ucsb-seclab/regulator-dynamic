#include <iostream>

#include "v8.h"
#include "regexp-executor.hpp"

#include "catch.hpp"


namespace e = regulator::executor;


TEST_CASE( "Should show some coverage" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("fo[o]+", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result;
    e::Result exec_result_status = e::Exec(&regexp, "foooooooooooo", 13, &exec_result);
    
    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.coverage_tracker != nullptr );
    // probably should have covered more than one basic block transition
    REQUIRE( exec_result.coverage_tracker->Popcount() > 1);
}

TEST_CASE( "Coverage should increase as regexp match progresses" )
{
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("a(b|c)d(e|f)+g.", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result1;
    e::Result exec_result_status = e::Exec(&regexp, "ab      ", 8, &exec_result1);

    REQUIRE( exec_result_status == e::kSuccess );
    
    e::V8RegExpResult exec_result2;
    exec_result_status = e::Exec(&regexp, "abdefgh ", 8, &exec_result2);

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result2.coverage_tracker->Popcount() > exec_result1.coverage_tracker->Popcount() );
    REQUIRE( exec_result1.coverage_tracker->HasNewPath(exec_result2.coverage_tracker) );

    regulator::fuzz::CoverageTracker union_;
    union_.Union(exec_result1.coverage_tracker);
    union_.Union(exec_result2.coverage_tracker);

    REQUIRE( union_.Popcount() < exec_result1.coverage_tracker->Popcount() + exec_result2.coverage_tracker->Popcount() );
    REQUIRE( union_.Popcount() > 0 );
    REQUIRE( union_.Popcount() > exec_result1.coverage_tracker->Popcount() );
    REQUIRE( union_.Popcount() > exec_result2.coverage_tracker->Popcount() );
    REQUIRE_FALSE( union_.HasNewPath(exec_result1.coverage_tracker) );
    REQUIRE_FALSE( union_.HasNewPath(exec_result2.coverage_tracker) );
}
