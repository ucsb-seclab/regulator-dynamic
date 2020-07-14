#include "regexp-executor.hpp"
#include "interesting-char-finder.hpp"

#include "catch.hpp"
namespace e = regulator::executor;
namespace f = regulator::fuzz;

TEST_CASE( "basic interesting chars" )
{
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    std::string pattern = "ab+c[d-f]gh?(e)";
    std::string flags = "";
    e::Result result = e::Compile(pattern.c_str(), flags.c_str(), &regexp);

    REQUIRE( result == e::kSuccess );
    
    std::vector<uint8_t> interesting;
    bool extract_ok = f::ExtractInteresting(regexp, interesting);

    REQUIRE( extract_ok );

    REQUIRE( interesting.size() > 0 );
}


TEST_CASE( "test interesting CHECK_CHAR_NOT_IN_RANGE" )
{
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    std::string pattern = "f[o-s]x";
    std::string flags = "";
    e::Result result = e::Compile(pattern.c_str(), flags.c_str(), &regexp);

    REQUIRE( result == e::kSuccess );

    std::vector<uint8_t> interesting;
    bool extract_ok = f::ExtractInteresting(regexp, interesting);

    REQUIRE( extract_ok );

    REQUIRE( interesting.size() > 0 );

    bool has_o = false;
    bool has_s = false;

    for (size_t i=0; i<interesting.size(); i++)
    {
        has_o = has_o || interesting[i] == 'o';
        has_s = has_s || interesting[i] == 's';
    }

    REQUIRE( has_o );
    REQUIRE( has_s );
}


TEST_CASE( "test bit twiddling in AND_CHECK_CHAR" )
{
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    std::string pattern = "[bc]d";
    std::string flags = "";
    e::Result result = e::Compile(pattern.c_str(), flags.c_str(), &regexp);

    REQUIRE( result == e::kSuccess );

    std::vector<uint8_t> interesting;
    bool extract_ok = f::ExtractInteresting(regexp, interesting);

    REQUIRE( extract_ok );

    REQUIRE( interesting.size() > 0 );

    bool has_b = false;
    bool has_c = false;

    for (size_t i=0; i<interesting.size(); i++)
    {
        has_b = has_b || interesting[i] == 'b';
        has_c = has_c || interesting[i] == 'c';
    }

    REQUIRE( has_b );
    REQUIRE( has_c );
}


TEST_CASE( "test SKIP_UNTIL_CHAR_POS_CHECKED" )
{
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    std::string pattern = "a.+b";
    std::string flags = "";
    e::Result result = e::Compile(pattern.c_str(), flags.c_str(), &regexp);

    REQUIRE( result == e::kSuccess );

    std::vector<uint8_t> interesting;
    bool extract_ok = f::ExtractInteresting(regexp, interesting);

    REQUIRE( extract_ok );

    REQUIRE( interesting.size() > 0 );

    bool has_a = false;

    for (size_t i=0; i<interesting.size(); i++)
    {
        has_a = has_a || interesting[i] == 'a';
    }

    REQUIRE( has_a );
}


TEST_CASE( "test a vulnerable regex for special chars" )
{
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    std::string pattern = "\\d+1\\d+2(b|bb)+c";
    std::string flags = "";
    e::Result result = e::Compile(pattern.c_str(), flags.c_str(), &regexp);

    REQUIRE( result == e::kSuccess );

    std::vector<uint8_t> interesting;
    std::cout << std::endl << std::endl;
    bool extract_ok = f::ExtractInteresting(regexp, interesting);

    REQUIRE( extract_ok );

    REQUIRE( interesting.size() > 0 );

    bool has_a = false;

    for (size_t i=0; i<interesting.size(); i++)
    {
        has_a = has_a || interesting[i] == 'a';
        std::cout << interesting[i] << std::endl;
    }

    REQUIRE( has_a );
}