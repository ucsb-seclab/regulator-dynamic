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
#include <vector>

#include "corpus.hpp"

namespace regulator
{
namespace fuzz
{

/**
 * Generate `n` children derived by mutating `parent`.
 */
void GenChildren(
    Corpus *corpus,
    size_t parent_idx,
    size_t n_children,
    ::std::vector<uint8_t *> &vec);

/**
 * Select one byte and mutate it to some random value
 */
void mutate_random_byte(uint8_t *buf, size_t buflen);

/**
 * Add (or subtract) some value -8 <= v <= 8, v /= 0
 * at a random position.
 */
void arith_random_byte(uint8_t *buf, size_t buflen);

/**
 * Swap a byte with another one.
 */
void swap_random_bytes(uint8_t *buf, size_t buflen);

/**
 * Flip one random bit.
 */
void bit_flip(uint8_t *buf, size_t buflen);

/**
 * Select another item, at random, from the corpus, and copy a random substring
 * into buf at the same location.
 */
void crossover(uint8_t *buf, size_t buflen, Corpus *corpus);

}
}
