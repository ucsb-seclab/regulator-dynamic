// tests execution with different flags

#include "regexp-executor.hpp"

#include "catch.hpp"

namespace e = regulator::executor;
namespace f = regulator::fuzz;

TEST_CASE( "compile and exec with case-insensitive (8-bit)" )
{
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    std::string sz_regexp = "foo.+bar";
    e::Result compile_result_status = e::Compile(sz_regexp.c_str(), "i", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    uint8_t negative_subject[] = {
        'f',
        'f',
        'o',
        'o',
        'b',
        'a',
        'r'
    };
    uint8_t positive_subject[] = {
        'f',
        'F',
        'o',
        'O',
        '_',
        'B',
        'a',
        'R',
        'x'
    };

    e::Result exec_result_status;
    e::V8RegExpResult exec_result;

    exec_result_status = e::Exec(
        &regexp,
        negative_subject,
        sizeof(negative_subject),
        exec_result,
        e::kOnlyOneByte
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == false );

    exec_result_status = e::Exec(
        &regexp,
        positive_subject,
        sizeof(positive_subject),
        exec_result,
        e::kOnlyOneByte
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.match_success == true );
}

TEST_CASE( "compile and exec with sticky bit " )
{
}
