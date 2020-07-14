// regexp_executor.hpp
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Functionality to prepare and execute a regular expression
// using the v8 regexp bytecode engine

#pragma once

#include <stdint.h>

#include "src/objects/js-regexp.h"
#include "fuzz/coverage-tracker.hpp"


namespace regulator
{
namespace executor
{


enum Result {
    kSuccess,
    kNotValidString,
    kCouldNotCompile,
    kBadStrRepresentation,
};

enum RepresentationUsed {
    kRepOneByte,
    kRepTwoByte,
};

enum EnforceRepresentation {
    kAnyRepresentation,
    kOnlyOneByte,
    kOnlyTwoByte,
};


class V8RegExp {
public:
    V8RegExp();

    v8::internal::Handle<v8::internal::JSRegExp> regexp;
};

class V8RegExpResult {
public:
    V8RegExpResult();
    ~V8RegExpResult();

    bool match_success;
    RepresentationUsed rep_used;
    regulator::fuzz::CoverageTracker *coverage_tracker;
};

/**
 * Initialize the V8 runtime. This should be called before any regexp operations
 * are performed.
 * 
 * This method is idempotent and can be called multiple times.
 */
v8::Isolate *Initialize();

/**
 * Compiles the given character string (interpreted as utf8) to a regexp, and
 * puts the result in `out`. Returns an indicator of success / failure.
 */
Result Compile(const char *pattern, const char *flags, V8RegExp *out);


template<typename Char>
Result Exec(
    V8RegExp *regexp,
    const Char *subject,
    size_t subject_len,
    V8RegExpResult *out,
    EnforceRepresentation rep = kAnyRepresentation);

}
}
