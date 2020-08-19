// Contains tests for the information that CoverageTracker reports
// about the 'meta' state of the coverage tracker -- non-coverage
// information about how the execution flow happened

#include "fuzz/coverage-tracker.hpp"
#include "regexp-executor.hpp"

#include "catch.hpp"
#include <vector>
#include <memory>
#include <iostream>

namespace f = regulator::fuzz;
namespace e = regulator::executor;

TEST_CASE( "CoverageTracker should report where we would expect the matching rejects / matches [SIMPLE]" )
{
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("abcdef.", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result;
    std::string subject = "xxaxcdefxxxxxxxxxxxxxxx";
    e::Result exec_result_status = e::Exec<uint8_t>(
        &regexp,
        reinterpret_cast<const uint8_t *>(subject.c_str()),
        subject.length(),
        exec_result
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == false );

    std::vector<f::suggestion> suggestions;
    exec_result.coverage_tracker->GetSuggestions(suggestions);
    REQUIRE( suggestions.size() > 0 );

    bool found_expected_suggestion = false;

    for (size_t i=0; i < suggestions.size(); i++)
    {
        if (static_cast<char>(suggestions[i].c) == 'b' && suggestions[i].pos == 3)
        {
            found_expected_suggestion = true;
        }
    }

    REQUIRE( found_expected_suggestion == true );

}


TEST_CASE( "CoverageTracker should report where we would expect the matching rejects / matches (16-bit)" )
{
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("abcdef.", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result;
    uint16_t *buf = new uint16_t[20];
    std::unique_ptr<uint16_t[]> auto_release(buf);
    for (size_t i=0; i < 20; i++)
    {
        buf[i] = 'x';
    }
    buf[2] = 'a';
    buf[3] = 'x';
    buf[4] = 'c';
    buf[5] = 'd';
    buf[6] = 'e';
    buf[7] = 'f';
    buf[8] = 0xfe12;

    e::Result exec_result_status = e::Exec<uint16_t>(
        &regexp,
        buf,
        20,
        exec_result
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == false );

    std::vector<f::suggestion> suggestions;
    exec_result.coverage_tracker->GetSuggestions(suggestions);
    REQUIRE( suggestions.size() > 0 );

    bool found_expected_suggestion = false;

    for (size_t i=0; i < suggestions.size(); i++)
    {
        if (static_cast<char>(suggestions[i].c) == 'b' && suggestions[i].pos == 3)
        {
            found_expected_suggestion = true;
        }
    }

    REQUIRE( found_expected_suggestion == true );

}
