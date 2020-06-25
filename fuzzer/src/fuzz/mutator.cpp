#include "mutator.hpp"

#include <cstdint>
#include <random>
#include <cmath>
#include <cstring>

namespace regulator
{
namespace fuzz
{

void havoc_random_byte(uint8_t *buf, size_t buflen)
{
    size_t addr = static_cast<size_t>(random()) % buflen;
    buf[addr] = static_cast<uint8_t>(random());
}

void duplicate_random_substr(uint8_t *buf, size_t buflen)
{
    size_t src_addr = static_cast<size_t>(random()) % buflen;
    size_t dst_addr;
    do
    {
        dst_addr = static_cast<size_t>(random()) % buflen;
    } while (dst_addr == src_addr);

    size_t len = std::min(
        buflen - src_addr,
        static_cast<size_t>(random()) % (buflen / 2) + 1
    );

    // todo: make this not use heap space...
    uint8_t *cpy = new uint8_t[len];
    memcpy(cpy, buf + src_addr, len);
    memcpy(buf + dst_addr, cpy, len);
    delete[] cpy;
}

}
}
