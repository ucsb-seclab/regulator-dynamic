// test-deep-fuzz.cpp
//
// contains tests which probe the behavior of fuzzing for deeper behavior
//

#include "v8.h"
#include "regexp-executor.hpp"
#include "fuzz/coverage-tracker.hpp"
#include "src/regexp/regexp-interpreter.h"

#include "catch.hpp"

namespace e = regulator::executor;
namespace f = regulator::fuzz;

TEST_CASE( "expanding on hidden catastrophic backtracking is rewarded" )
{
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    std::string sz_regexp = "\\d+1\\d+2(b|\\w)+c";
    e::Result compile_result_status = e::Compile(sz_regexp.c_str(), "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::Result exec_result_status;
    e::V8RegExpResult exec_result;

    uint8_t success_match[10] = {'1', '1', '1', '1', '1', '1', '2', 'b', 'b', 'c'};
    exec_result_status = e::Exec(
        &regexp,
        success_match,
        sizeof(success_match),
        exec_result,
        e::kOnlyOneByte
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == true );

    // all 1's, which triggers the O(n^2) behavior at the beginning
    // of the regexp
    uint8_t basic_input[11] = { '1' };
    exec_result_status = e::Exec(
        &regexp,
        basic_input,
        sizeof(basic_input),
        exec_result,
        e::kOnlyOneByte
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == false );
    
    f::CoverageTracker covtrack_1(*exec_result.coverage_tracker);

    // v8::internal::FLAG_trace_regexp_bytecodes = true;

    uint8_t deeper_input[11] = { '2', '2', '2', '2', '1', '1', '2', 'b', 'b', 'b', 'b' };
    exec_result_status = e::Exec(
        &regexp,
        deeper_input,
        sizeof(deeper_input),
        exec_result,
        e::kOnlyOneByte
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == false );
    
    f::CoverageTracker covtrack_2(*exec_result.coverage_tracker);

    REQUIRE( covtrack_1.Total() < covtrack_2.Total() );
    REQUIRE( covtrack_1.HasNewPath(&covtrack_2) );

    uint8_t even_deeper_input[11] =  { '2', '1', '1', '2', 'b', 'b', 'b', 'b', 'b', 'b', 'b' };
    exec_result_status = e::Exec(
        &regexp,
        even_deeper_input,
        sizeof(even_deeper_input),
        exec_result,
        e::kOnlyOneByte
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == false );

    REQUIRE( covtrack_2.HasNewPath(exec_result.coverage_tracker.get()) );
    REQUIRE( covtrack_2.Total() < exec_result.coverage_tracker->Total() );

    v8::internal::FLAG_trace_regexp_bytecodes = false;
}
