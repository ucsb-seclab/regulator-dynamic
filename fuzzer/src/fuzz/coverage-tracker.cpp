#include "coverage-tracker.hpp"

#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <cstring>


namespace regulator
{
namespace fuzz
{

constexpr uint32_t num_bytes_to_alloc = (1 << MAX_CODE_SIZE) / 8 + 1;

CoverageTracker::CoverageTracker()
{
    this->bitfield = reinterpret_cast<uint8_t *>(malloc(num_bytes_to_alloc));
    this->Clear();
}

CoverageTracker::CoverageTracker(const CoverageTracker &other)
{
    this->bitfield = reinterpret_cast<uint8_t *>(malloc(num_bytes_to_alloc));
    memcpy(this->bitfield, other.bitfield, num_bytes_to_alloc);
}


CoverageTracker::~CoverageTracker()
{
    free(this->bitfield);
}

void CoverageTracker::Cover(uintptr_t src_addr, uintptr_t dst_addr)
{
    const uint32_t bit_to_set = REGULATOR_FUZZ_TRANSFORM_ADDR(src_addr) ^
                                REGULATOR_FUZZ_TRANSFORM_ADDR(dst_addr);
    this->bitfield[bit_to_set / 8] |= 1 << (bit_to_set & (8 - 1));
}

uint32_t CoverageTracker::Popcount()
{
    uint32_t ret = 0;
    for (size_t i=0; i < num_bytes_to_alloc; i++)
    {
        // todo: do some loop unrolling here
        ret += __builtin_popcount(this->bitfield[i]);
    }
    return ret;
}

void CoverageTracker::Clear()
{
    memset(this->bitfield, 0, num_bytes_to_alloc);
}


void CoverageTracker::Union(CoverageTracker *other)
{
    // Just OR the whole thing -- easy enough
    // todo: do some loop unrolling here
    for (size_t i=0; i < num_bytes_to_alloc; i++)
    {
        this->bitfield[i] |= other->bitfield[i];
    }
}

bool CoverageTracker::HasNewPath(CoverageTracker *other)
{
    // if `other` has ANY bits in their bit-field we don't,
    // then it's novel
    for (size_t i=0; i < num_bytes_to_alloc; i++)
    {
        if ((other->bitfield[i] & (~this->bitfield[i])) != 0)
        {
            return true;
        }
    }
    return false;
}

}
}