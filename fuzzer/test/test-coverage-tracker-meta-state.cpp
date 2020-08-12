// Contains tests for the information that CoverageTracker reports
// about the 'meta' state of the coverage tracker -- non-coverage
// information about how the execution flow happened

#include "fuzz/coverage-tracker.hpp"
#include "regexp-executor.hpp"

#include "catch.hpp"

namespace f = regulator::fuzz;
namespace e = regulator::executor;

TEST_CASE( "CoverageTracker should report where we would expect the matching rejects / matches [SIMPLE]" )
{
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
        subject.length(),
        exec_result
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == true );
    REQUIRE( exec_result.coverage_tracker->FinalCursorPosition() > 0 );
    REQUIRE( exec_result.coverage_tracker->FinalCursorPosition() < SIZE_MAX );

    e::V8RegExpResult exec_result2;
    subject = "xxxxxxxxxfooxxxxxxxxxxx";
    exec_result_status = e::Exec<uint8_t>(
        &regexp,
        reinterpret_cast<const uint8_t *>(subject.c_str()),
        subject.length(),
        exec_result2
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result2.match_success == true );
    REQUIRE( exec_result2.coverage_tracker->FinalCursorPosition() > 8 );
    REQUIRE( exec_result2.coverage_tracker->FinalCursorPosition() < 13 );
}
