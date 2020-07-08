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
template<typename Char>
void GenChildren(
    Corpus<Char> *corpus,
    size_t parent_idx,
    size_t n_children,
    ::std::vector<Char *> &vec);

/**
 * Select one byte and mutate it to some random value
 */
template<typename Char>
void mutate_random_byte(Char *buf, size_t buflen);

/**
 * Add (or subtract) some value -8 <= v <= 8, v /= 0
 * at a random position.
 */
template<typename Char>
void arith_random_byte(Char *buf, size_t buflen);

/**
 * Swap a byte with another one.
 */
template<typename Char>
void swap_random_bytes(Char *buf, size_t buflen);

/**
 * Flip one random bit.
 */
template<typename Char>
void bit_flip(Char *buf, size_t buflen);

/**
 * Select another item, at random, from the corpus, and copy a random substring
 * into buf at the same location.
 * 
 * avoid_original_parent is the index of the parent CorpusEntry, which will
 * be avoided for crossover
 */
template<typename Char>
void crossover(Char *buf, size_t buflen, Corpus<Char> *corpus, size_t avoid_original_parent);

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
void replace_with_special(Char *buf, size_t buflen);


/**
 * Rotate the string by one character in a randomly
 * chosen direction (left or right).
 */
template<typename Char>
void rotate_once(Char *buf, size_t buflen);

}
}
