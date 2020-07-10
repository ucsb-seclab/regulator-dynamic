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
 * 
 * NOTE: `coparent_buffer` MUST have at least `n_children` items in
 * it. If a child is generated via crossover mutation, a coparent
 * is selected (without replacement) by popping from the back of
 * the `coparent_buffer`.
 * 
 * Any buffers removed from `coparent_buffer` are deleted.
 * 
 * @param parent the parent buffer
 * @param parent_len the number of `Char`s in the parent buffer
 * @param n_children the number of children to generate
 * @param coparent_buffer a list of entries to potentially use as co-parents
 *   when doing crossover mutation
 * @param extra_interesting a list of extra "interesting" char values which
 *   we will also use when doing an "interesting value replacement" mutation
 * @param out stores the generated children
 */
template<typename Char>
void GenChildren(
    Char *parent,
    size_t parent_len,
    size_t n_children,
    ::std::vector<Char *> &coparent_buffer,
    ::std::vector<Char> &extra_interesting,
    ::std::vector<Char *> &out);

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
void swap_random_chars(Char *buf, size_t buflen);

/**
 * Flip one random bit.
 */
template<typename Char>
void bit_flip(Char *buf, size_t buflen);

/**
 * Pop the last item in the buffer and copy a random substring of it
 * into buf at the same location.
 */
template<typename Char>
void crossover(Char *buf, size_t buflen, std::vector<Char *> &coparent_buffer);

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
