// regexp_executor.hpp
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Functionality to prepare and execute a regular expression
// using the v8 regexp bytecode engine

#pragma once

#include <stdint.h>

#include "src/objects/js-regexp.h"

namespace regulator
{
namespace executor
{


enum Result {
    kSuccess,
    kNotValidUtf8,
    kCouldNotCompile,
};


class V8RegExp {
public:
    V8RegExp();

    v8::internal::Handle<v8::internal::JSRegExp> regexp;
};

class V8RegExpResult {
public:
    V8RegExpResult();

    bool match_success;
    uint64_t opcount;
    v8::internal::MaybeHandle<v8::internal::RegExpMatchInfo> match;
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


Result Exec(V8RegExp *regexp, char *subject, size_t subject_len, V8RegExpResult *out);

}
}
