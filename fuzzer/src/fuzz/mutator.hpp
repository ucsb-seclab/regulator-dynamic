// mutator.hpp
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Very simple bytestring mutator for fuzzing fixed-length
// inputs.
//

#pragma once

#include <cstdint>
#include <cstring>

namespace regulator
{
namespace fuzz
{

/**
 * Select one byte and mutate it to some random value
 */
void havoc_random_byte(uint8_t *buf, size_t buflen);

/**
 * Select a random substring (with 0 < size < buflen / 2)
 * and duplicate it elsewhere in the buffer, where it _may_
 * overlap with other data.
 */
void duplicate_random_substr(uint8_t *buf, size_t buflen);

}
}
