#pragma once

#include "v8.h"
#include "regexp-executor.hpp"

namespace regulator
{
namespace fuzz
{

/**
 * Fuzzes the given input regexp for longest known execution time
 * 
 * @param isolate the isolate
 * @param regexp the compiled regular expression
 * @param strlen target string length, in bytes
 * @param fuzz_one_byte when true, fuzz one-byte strings
 * @param fuzz_two_byte when true, fuzz two-byte strings
 * 
 * @returns the worst-case opcount
 */
uint64_t Fuzz(
    v8::Isolate *isolate,
    regulator::executor::V8RegExp *regexp,
    size_t strlen,
    bool fuzz_one_byte = true,
    bool fuzz_two_byte = true,
    uint16_t n_threads = 1
);

}
}
