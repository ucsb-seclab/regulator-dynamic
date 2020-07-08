#include "mutator.hpp"

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
const char interesting_one_byte[] = {
    ' ', '\t', '\n', '\r', '\v',    // whitespaces
    'a', 'z', 'A', 'Z',             // letters
    '1', '2',                       // digits
    '~', '!', '\\', '/', '"', '\'', // special chars
    '\xe8', /* e with grave accent */
    '\xbe', /* three quarters mark */
    '\xb2', /* superscript two */
    '\x80', /* euro */
    '\xdc', /* uppercase U with umlaut */
    '\xd7', /* times symbol */
};

const uint16_t interesting_two_byte[] = {
    0x6600, // 'f'
    0x3100, // '1'
    0x0d00, // '\r'
    0x0a00, // '\n'
    0x0900, // '\t'
    0x2000, // ' '
    0x2100, // '!'
    0xac20, // euro sign
    0x0326, 0x0ffe, // snowman emoji
    0x3dd8, 0x93dc, // beating heart emoji
};

template<typename Char>
void GenChildren(
    Corpus<Char> *corpus,
    size_t parent_idx,
    size_t n_children,
    ::std::vector<Char *> &vec)
{
    // NOTE: each child is a mutation OF THE PREVIOUS GENERATED CHILD

    CorpusEntry<Char> *parent = corpus->Get(parent_idx);
    Char *last_buf = parent->buf;
    size_t buflen = parent->buflen;

    for (size_t i = 0; i < n_children; i++)
    {
        Char *newbuf = new Char[buflen];
        memcpy(newbuf, last_buf, buflen * sizeof(Char));

        // select a mutation to apply
        switch (random() % 8)
        {
        case 0:
            mutate_random_byte(newbuf, buflen);
            break;
        case 1:
            arith_random_byte(newbuf, buflen);
            break;
        case 2:
            swap_random_bytes(newbuf, buflen);
            break;
        case 3:
            bit_flip(newbuf, buflen);
            break;
        case 4:
            crossover(newbuf, buflen, corpus, parent_idx);
            break;
        case 5:
            duplicate_subsequence(newbuf, buflen);
            break;
        case 6:
            replace_with_special(newbuf, buflen);
            break;
        case 7:
            rotate_once(newbuf, buflen);
            break;
        default:
            throw "Unreachable";
        }

        last_buf = newbuf;
        vec.push_back(newbuf);
    }
}

template<typename Char>
void mutate_random_byte(Char *buf, size_t buflen)
{
    size_t addr = static_cast<size_t>(random()) % buflen;
    buf[addr] = static_cast<Char>(random());
}


template<typename Char>
void arith_random_byte(Char *buf, size_t buflen)
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
void swap_random_bytes(Char *buf, size_t buflen)
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
void bit_flip(Char *buf, size_t buflen)
{
    size_t addr = static_cast<size_t>(random()) % buflen;
    Char bit = static_cast<uint8_t>(random()) % (sizeof(Char) * 8);
    buf[addr] ^= static_cast<size_t>(1) << bit;
}

template<typename Char>
void crossover(Char *buf, size_t buflen, Corpus<Char> *corpus, size_t avoid_original_parent)
{
    if (corpus->Size() == 1)
    {
        // no co-parents are available
        return;
    }

    size_t src = static_cast<size_t>(random()) % buflen;
    // end is exclusive
    size_t end = static_cast<size_t>(random()) % buflen;

    if (src > end)
    {
        size_t tmp = src;
        src = end;
        end = tmp;
    }
    // make end exclusive (so end can be `buflen` at most)
    end++;

    size_t coparent_idx;
    do
    {
        coparent_idx = static_cast<size_t>(random()) % (corpus->Size());
    } while (coparent_idx == avoid_original_parent);

    CorpusEntry<Char> *co_parent = corpus->Get(coparent_idx);

    for (size_t i = src; i < buflen && i < end; i++)
    {
        buf[i] = co_parent->buf[i];
    }
}

template<typename Char>
void duplicate_subsequence(Char *buf, size_t buflen)
{
    size_t src = static_cast<size_t>(random()) % buflen;
    // end is exclusive
    size_t end = src + static_cast<size_t>(random()) % (buflen - src);

    size_t len = end - src;
    size_t dst = static_cast<size_t>(random()) % (buflen - len);

    uint8_t *tmp = new uint8_t[len];
    memcpy(tmp, buf + src, len);
    memcpy(buf + dst, tmp, len);
    delete[] tmp;
}


template<typename Char>
void replace_with_special(Char *buf, size_t buflen)
{
    Char c;
    if (sizeof(Char) == 1)
    {
        c = interesting_one_byte[random() % (sizeof(interesting_one_byte))];
    }
    else
    {
        c = interesting_two_byte[random() % (sizeof(interesting_two_byte) / sizeof(Char))];
    }

    size_t i = static_cast<size_t>(random()) % buflen;
    buf[i] = c;
}


template<typename Char>
void rotate_once(Char *buf, size_t buflen)
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

template void GenChildren<uint8_t>(
    Corpus<uint8_t> *corpus,
    size_t parent_idx,
    size_t n_children,
    ::std::vector<uint8_t *> &vec);

template void GenChildren<uint16_t>(
    Corpus<uint16_t> *corpus,
    size_t parent_idx,
    size_t n_children,
    ::std::vector<uint16_t *> &vec);

}
}
