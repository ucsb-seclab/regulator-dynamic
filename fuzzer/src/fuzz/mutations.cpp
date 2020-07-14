#include "mutations.hpp"

#include <cstdint>
#include <random>
#include <cmath>
#include <cstring>
#include <iostream>

namespace regulator
{
namespace fuzz
{

/**
 * Contains interesting chars to insert
 */
const uint8_t interesting_one_byte[] = {
    ' ', '\t', '\n', '\r', '\v',    // whitespaces
    0xe8, // e with grave accent
    0xbe, // three quarters mark
    0xb2, // superscript two
    0x80, // euro
    0xdc, // uppercase U with umlaut
    0xd7, // times symbol
    0xff, // all bits set
};

const uint16_t interesting_two_byte[] = {
    0x0066, // 'f'
    0x0031, // '1'
    0x000d, // '\r'
    0x000a, // '\n'
    0x0009, // '\t'
    0x0020, // ' '
    0x0021, // '!'
    0x01d4, // small letter u with caron
    0x2603, 0xfe0f, // snowman emoji
    0xd83d, 0xdc93, // beating heart emoji
    0xffff, // all bits set
};


template<typename Char>
inline void mutate_random_char(Char *buf, size_t buflen)
{
    size_t addr = static_cast<size_t>(random()) % buflen;
    buf[addr] = static_cast<Char>(random());
}

template<typename Char>
inline void arith_random_char(Char *buf, size_t buflen)
{
    size_t addr = static_cast<size_t>(random()) % buflen;
    int8_t to_add = static_cast<int8_t>(static_cast<uint8_t>(random())) & 0xf - 8;
    if (to_add == 0)
    {
        to_add = 8;
    }

    buf[addr] += to_add;
}

template<typename Char>
inline void swap_random_char(Char *buf, size_t buflen)
{
    size_t src = static_cast<size_t>(random()) % buflen;
    size_t dst;
    do
    {
        dst = static_cast<size_t>(random()) % buflen;
    } while (dst == src);

    Char tmp = buf[src];
    buf[src] = buf[dst];
    buf[dst] = buf[src];
}

template<typename Char>
inline void bit_flip(Char *buf, size_t buflen)
{
    size_t addr = static_cast<size_t>(random()) % buflen;
    Char bit = static_cast<uint8_t>(random()) % (sizeof(Char) * 8);
    buf[addr] ^= static_cast<size_t>(1) << bit;
}

template<typename Char>
inline void crossover(Char *buf, size_t buflen, Char *&coparent)
{
    size_t src = static_cast<size_t>(random()) % buflen;
    // end is exclusive
    size_t end = static_cast<size_t>(random()) % buflen;

    // if src & end are out-of-order then swap them into order
    if (src > end)
    {
        size_t tmp = src;
        src = end;
        end = tmp;
    }

    // make end exclusive (so end can be `buflen` at most)
    end++;

    for (size_t i = src; i < buflen && i < end; i++)
    {
        buf[i] = coparent[i];
    }
}

template<typename Char>
inline void duplicate_subsequence(Char *buf, size_t buflen)
{
    if (buflen == 1)
    {
        // nothing to do
        return;
    }

    // to avoid selecting the whole thing, ensure the substring
    // length is in the inclusive range [1, buflen-1]
    size_t substr_len = static_cast<size_t>(random()) % (buflen - 1) + 1;

    // now, select where the substring should start (any index from 0 to
    // buflen - substr_len)
    size_t src = static_cast<size_t>(random()) % ((buflen - substr_len) + 1);

    // select a destination index which isn't src
    size_t dst;
    do
    {
        dst = static_cast<size_t>(random()) % ((buflen - substr_len) + 1);
    } while (src == dst);

    Char *tmp = new Char[substr_len * sizeof(Char)];
    memcpy(tmp, buf + src, substr_len * sizeof(Char));
    memcpy(buf + dst, tmp, substr_len * sizeof(Char));
    delete[] tmp;
}


inline void get_interesting_arr(const uint8_t *&ptr, size_t &len)
{
    ptr = interesting_one_byte;
    len = sizeof(interesting_one_byte);
}

inline void get_interesting_arr(const uint16_t *&ptr, size_t &len)
{
    ptr = interesting_two_byte;
    len = sizeof(interesting_two_byte) / sizeof(uint16_t);
}

template<typename Char>
inline void replace_with_special(Char *buf, size_t buflen, std::vector<Char> &extra_interesting)
{
    const Char *interesting_arr;
    size_t num_builtin_interesting;
    get_interesting_arr(interesting_arr, num_builtin_interesting);

    Char c;

    size_t chosen_idx = static_cast<size_t>(random()) % (num_builtin_interesting + extra_interesting.size());

    if (chosen_idx >= num_builtin_interesting)
    {
        c = extra_interesting[chosen_idx - num_builtin_interesting];
    }
    else
    {
        c = interesting_arr[chosen_idx];
    }

    size_t i = static_cast<size_t>(random()) % buflen;
    buf[i] = c;
}


template<typename Char>
inline void rotate_once(Char *buf, size_t buflen)
{
    // when = +1, rotates left
    // when = -1, rotates right
    int direction = ((static_cast<int>(random()) & 0x1) * 2) - 1;

    // which end of the buffer to start on?
    // when rotating left,  0
    // when rotating right, buflen
    size_t curr = direction == 1 ? 0 : buflen;

    // store the end char (We overwrite it)
    Char tmp = buf[curr];

    for (size_t i=0; i < buflen - 1; i++)
    {
        buf[curr] = buf[curr + direction];
        curr += direction;
    }

    // restore the end char (now on the opposite side)
    buf[curr] = tmp;
}

template void mutate_random_char(uint8_t *buf, size_t buflen);
template void arith_random_char(uint8_t *buf, size_t buflen);
template void swap_random_char(uint8_t *buf, size_t buflen);
template void bit_flip(uint8_t *buf, size_t buflen);
template void crossover(uint8_t *buf, size_t buflen, uint8_t *&coparent);
template void duplicate_subsequence(uint8_t *buf, size_t buflen);
template void replace_with_special(uint8_t *buf, size_t buflen, std::vector<uint8_t> &extra_interesting);
template void rotate_once(uint8_t *buf, size_t buflen);

template void mutate_random_char(uint16_t *buf, size_t buflen);
template void arith_random_char(uint16_t *buf, size_t buflen);
template void swap_random_char(uint16_t *buf, size_t buflen);
template void bit_flip(uint16_t *buf, size_t buflen);
template void crossover(uint16_t *buf, size_t buflen, uint16_t *&coparent);
template void duplicate_subsequence(uint16_t *buf, size_t buflen);
template void replace_with_special(uint16_t *buf, size_t buflen, std::vector<uint16_t> &extra_interesting);
template void rotate_once(uint16_t *buf, size_t buflen);

}
}
