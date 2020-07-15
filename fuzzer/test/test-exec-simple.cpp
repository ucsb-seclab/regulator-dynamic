#include <iostream>

#include "fuzz/coverage-tracker.hpp"
#include "regexp-executor.hpp"
#include "v8.h"
#include "src/regexp/regexp-interpreter.h"

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
    std::string subject = "foo";
    e::Result exec_result_status = e::Exec<uint8_t>(
        &regexp,
        reinterpret_cast<const uint8_t *>(subject.c_str()),
        3,
        &exec_result
    );

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
    std::string subject = "bar";
    e::Result exec_result_status = e::Exec<uint8_t>(
        &regexp,
        reinterpret_cast<const uint8_t *>(subject.c_str()),
        3,
        &exec_result
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == false );
}

TEST_CASE( "opcount should increase as match generally increases" ) {
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    REQUIRE(v8::internal::coverage_tracker == nullptr);

    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("foo+", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE( v8::internal::coverage_tracker == nullptr );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result1;
    std::string subject = "foo";
    e::Result exec_result_status = e::Exec<uint8_t>(
        &regexp,
        reinterpret_cast<const uint8_t *>(subject.c_str()),
        3,
        &exec_result1
    );
    size_t ops_1 = exec_result1.coverage_tracker->Total();
    exec_result1.coverage_tracker = nullptr;

    REQUIRE( exec_result_status == e::kSuccess );

    std::string subject2 = "fooooooooooo";
    e::V8RegExpResult exec_result2;
    exec_result_status = e::Exec<uint8_t>(
        &regexp,
        reinterpret_cast<const uint8_t *>(subject2.c_str()),
        subject2.size(),
        &exec_result2
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result2.coverage_tracker->Total() > ops_1 );
}


TEST_CASE( "can execute against 16-bit strings" )
{
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    REQUIRE(v8::internal::coverage_tracker == nullptr);

    e::V8RegExp regexp;
    std::string sz_regexp = "f\\u013e\\u013e[f]";
    e::Result compile_result_status = e::Compile(sz_regexp.c_str(), "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE( v8::internal::coverage_tracker == nullptr );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    uint16_t negative_subject[] = {
        0x013f,
        'f',
        'o',
        'o'
    };
    uint16_t positive_subject[] = {
        'f',
        0x013e,
        0x013e,
        'f'
    };

    e::Result exec_result_status;
    e::V8RegExpResult exec_result;

    exec_result_status = e::Exec(
        &regexp,
        negative_subject,
        4,
        &exec_result,
        e::kOnlyTwoByte
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == false );
    REQUIRE( exec_result.coverage_tracker != nullptr );

    regulator::fuzz::CoverageTracker old_covtrack(*exec_result.coverage_tracker);
    exec_result.coverage_tracker = nullptr;

    exec_result_status = e::Exec(
        &regexp,
        positive_subject,
        4,
        &exec_result,
        e::kOnlyTwoByte
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == true );
    REQUIRE( old_covtrack.HasNewPath(exec_result.coverage_tracker) );
}
