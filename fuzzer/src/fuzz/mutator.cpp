#include "mutator.hpp"

#include <cstdint>
#include <random>
#include <cmath>
#include <cstring>

namespace regulator
{
namespace fuzz
{

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
        switch (random() % 4)
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
        default:
            throw "Unreachable";
        }

        // last_buf = newbuf;
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

}
}
