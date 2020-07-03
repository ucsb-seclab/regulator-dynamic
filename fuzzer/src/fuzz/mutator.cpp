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
const char interesting[] = {
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

void GenChildren(
    Corpus *corpus,
    size_t parent_idx,
    size_t n_children,
    ::std::vector<uint8_t *> &vec)
{
    // NOTE: each child is a mutation OF THE PREVIOUS GENERATED CHILD

    CorpusEntry *parent = corpus->Get(parent_idx);
    uint8_t *last_buf = parent->buf;
    size_t buflen = parent->buflen;

    for (size_t i = 0; i < buflen; i++)
    {
        uint8_t *newbuf = new uint8_t[buflen];
        memcpy(newbuf, last_buf, buflen);

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
            crossover(newbuf, buflen, corpus);
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

void mutate_random_byte(uint8_t *buf, size_t buflen)
{
    size_t addr = static_cast<size_t>(random()) % buflen;
    buf[addr] = static_cast<uint8_t>(random());
}

void arith_random_byte(uint8_t *buf, size_t buflen)
{
    size_t addr = static_cast<size_t>(random()) % buflen;
    int8_t to_add = static_cast<int8_t>(static_cast<uint8_t>(random())) & 0xf - 8;
    if (to_add == 0)
    {
        to_add = 8;
    }

    buf[addr] += to_add;
}

void swap_random_bytes(uint8_t *buf, size_t buflen)
{
    size_t src = static_cast<size_t>(random()) % buflen;
    size_t dst;
    do
    {
        dst = static_cast<size_t>(random()) % buflen;
    } while (dst == src);

    uint8_t tmp = buf[src];
    buf[src] = buf[dst];
    buf[dst] = buf[src];
}

void bit_flip(uint8_t *buf, size_t buflen)
{
    size_t addr = static_cast<size_t>(random()) % buflen;
    uint8_t bit = static_cast<uint8_t>(random()) % 8;
    buf[addr] ^= 1 << bit;
}

void crossover(uint8_t *buf, size_t buflen, Corpus *corpus)
{
    size_t src = static_cast<size_t>(random()) % buflen;
    // end is exclusive
    size_t end = src + static_cast<size_t>(random()) % (buflen - src);

    CorpusEntry *co_parent = corpus->GetOne();
    for (size_t i = src; i < buflen && i < end; i++)
    {
        buf[i] = co_parent->buf[i];
    }
}

void duplicate_subsequence(uint8_t *buf, size_t buflen)
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

void replace_with_special(uint8_t *buf, size_t buflen)
{
    char c = interesting[random() % (sizeof(interesting))];
    size_t i = static_cast<size_t>(random()) % buflen;
    buf[i] = c;
}

void rotate_once(uint8_t *buf, size_t buflen)
{
    // when = +1, rotates left
    // when = -1, rotates right
    int direction = ((static_cast<int>(random()) & 0x1) * 2) - 1;

    // which end of the buffer to start on?
    // when rotating left,  0
    // when rotating right, buflen
    size_t curr = direction == 1 ? 0 : buflen;

    // store the end char (We overwrite it)
    uint8_t tmp = buf[curr];

    for (size_t i=0; i < buflen - 1; i++)
    {
        buf[curr] = buf[curr + direction];
        curr += direction;
    }

    // restore the end char (now on the opposite side)
    buf[curr] = tmp;
}

}
}
