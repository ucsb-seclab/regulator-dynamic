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
 * @param outbuf a pointer to a buffer of size `strlen` to store the worst-case string
 * @param strlen target string length, in bytes
 * 
 * @returns the worst-case opcount
 */
uint64_t Fuzz(v8::Isolate *isolate, regulator::executor::V8RegExp *regexp, uint8_t *outbuf, size_t strlen);

}
}
