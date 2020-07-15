// mutations.hpp
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
 * Select one char and mutate it to some random value
 */
template<typename Char>
void mutate_random_char(Char *buf, size_t buflen);

/**
 * Add (or subtract) some value -8 <= v <= 8, v /= 0
 * at a random position.
 */
template<typename Char>
void arith_random_char(Char *buf, size_t buflen);

/**
 * Swap a char with another one.
 */
template<typename Char>
void swap_random_char(Char *buf, size_t buflen);

/**
 * Flip one random bit.
 */
template<typename Char>
void bit_flip(Char *buf, size_t buflen);

/**
 * Copy a random substring from coparent into buf
 */
template<typename Char>
void crossover(Char *buf, size_t buflen, const Char * const &coparent);

/**
 * Select a substring of `buf` at random and replicate it elsewhere
 * in `buf` (potentially overlapping)
 */
template<typename Char>
void duplicate_subsequence(Char *buf, size_t buflen);


/**
 * Select a random character to replace with a "special" char
 */
template<typename Char>
void replace_with_special(Char *buf, size_t buflen, std::vector<Char> &extra_interesting);


/**
 * Rotate the string by one character in a randomly
 * chosen direction (left or right).
 */
template<typename Char>
void rotate_once(Char *buf, size_t buflen);

}
}
