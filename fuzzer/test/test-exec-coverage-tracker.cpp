#include <iostream>
#include <memory>

#include "v8.h"
#include "regexp-executor.hpp"
#include "src/regexp/regexp-interpreter.h"
#include "fuzz/corpus.hpp"
#include "fuzz/coverage-tracker.hpp"

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
    std::string subject = "foooooooooooo";
    e::Result exec_result_status = e::Exec<uint8_t>(
        &regexp,
        reinterpret_cast<const uint8_t *>(subject.c_str()),
        13,
        exec_result
    );
    
    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result.coverage_tracker != nullptr );
    // probably should have covered more than one basic block transition
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
    std::string subject1 = "ab      ";
    e::Result exec_result_status = e::Exec<uint8_t>(
        &regexp,
        reinterpret_cast<const uint8_t *>(subject1.c_str()),
        8,
        exec_result1
    );

    REQUIRE( exec_result_status == e::kSuccess );

    e::V8RegExpResult exec_result2;
    std::string subject2 = "abdefgh ";
    exec_result_status = e::Exec<uint8_t>(
        &regexp,
        reinterpret_cast<const uint8_t *>(subject2.c_str()),
        8,
        exec_result2
    );

    REQUIRE( exec_result_status == e::kSuccess );
    REQUIRE( exec_result1.coverage_tracker->HasNewPath(exec_result2.coverage_tracker.get()) );

    regulator::fuzz::CoverageTracker union_;
    union_.Union(exec_result1.coverage_tracker.get());
    union_.Union(exec_result2.coverage_tracker.get());

    REQUIRE_FALSE( union_.HasNewPath(exec_result1.coverage_tracker.get()) );
    REQUIRE_FALSE( union_.HasNewPath(exec_result2.coverage_tracker.get()) );
}

TEST_CASE( "Coverage oddity..." )
{
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    e::V8RegExp regexp;
    e::Result compile_result_status = e::Compile("hasOwnProperty.+", "", &regexp);

    REQUIRE( compile_result_status == e::kSuccess );
    REQUIRE_FALSE( regexp.regexp.is_null() );

    e::V8RegExpResult exec_result1;
    std::string subject1 = "aaaaaaaaaaaaaaaaaaaa"; // 20 'a' chars
    e::Result exec_result_status = e::Exec<uint8_t>(
        &regexp,
        reinterpret_cast<const uint8_t *>(subject1.c_str()),
        subject1.length(),
        exec_result1
    );

    REQUIRE( exec_result_status == e::kSuccess );

    regulator::fuzz::Corpus<uint8_t> corp;
    uint8_t *buf = new uint8_t[subject1.size()];
    memcpy(buf, subject1.c_str(), subject1.length());
    corp.Record(new regulator::fuzz::CorpusEntry<uint8_t>(
        buf,
        subject1.length(),
        new regulator::fuzz::CoverageTracker(*exec_result1.coverage_tracker.get())
    ));

    corp.FlushGeneration();

    REQUIRE( corp.Size() == 1 );

    std::string subject2 = "aaaaaaaaaaaaaaacaaaa"; // I would expect this to not have more coverage ...?
    exec_result_status = e::Exec<uint8_t>(
        &regexp,
        reinterpret_cast<const uint8_t *>(subject2.c_str()),
        subject2.length(),
        exec_result1
    );

    REQUIRE( exec_result_status == e::kSuccess );

    REQUIRE_FALSE( corp.HasNewPath(exec_result1.coverage_tracker.get()) );
}
