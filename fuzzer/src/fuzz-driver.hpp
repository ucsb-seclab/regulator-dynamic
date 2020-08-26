#pragma once

#include "v8.h"
#include "regexp-executor.hpp"

#include <vector>

namespace regulator
{
namespace fuzz
{

/**
 * Fuzzes the given input regexp for longest known execution time
 * 
 * @param isolate the isolate
 * @param regexp the compiled regular expression
 * @param strlens target string lengths, in bytes
 * @param timeout_secs maximum time to spend fuzzing
 * @param individual_timeout_secs maximum time to spend on an individual string length without making progress
 * @param fuzz_one_byte when true, fuzz one-byte strings
 * @param fuzz_two_byte when true, fuzz two-byte strings
 * 
 * @returns the worst-case opcount
 */
uint64_t Fuzz(
    v8::Isolate *isolate,
    regulator::executor::V8RegExp *regexp,
    std::vector<size_t> &strlens,
    int32_t timeout_secs,
    int32_t individual_timeout_secs,
    bool fuzz_one_byte = true,
    bool fuzz_two_byte = true,
    uint16_t n_threads = 1
);

}
}
