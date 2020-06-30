#include "coverage-tracker.hpp"

extern "C" {
    #include "murmur3.h"
}

#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <cstring>


namespace regulator
{
namespace fuzz
{

// NOTE: I believe this allocs one too many bytes
constexpr uint32_t num_bytes_to_alloc = 1 << MAX_CODE_SIZE;

CoverageTracker::CoverageTracker()
{
    this->path_hash = 0;
    this->total = 0;
    this->covmap = new uint8_t[num_bytes_to_alloc];
    this->Clear();
}

CoverageTracker::CoverageTracker(const CoverageTracker &other)
{
    this->total = other.total;
    this->covmap = new uint8_t[num_bytes_to_alloc];
    memcpy(this->covmap, other.covmap, num_bytes_to_alloc);
    this->path_hash = other.path_hash;
}


CoverageTracker::~CoverageTracker()
{
    delete[] this->covmap;
}


struct hash_data
{
    path_hash_t prev_hash;
    uintptr_t src_addr;
    uintptr_t dst_addr;
};


void CoverageTracker::Cover(uintptr_t src_addr, uintptr_t dst_addr)
{
    // AFL-style --
    src_addr *= 2;
    this->total++;
    const uint32_t bit_to_set = REGULATOR_FUZZ_TRANSFORM_ADDR(src_addr) ^
                                REGULATOR_FUZZ_TRANSFORM_ADDR(dst_addr);
    this->covmap[bit_to_set]++;

    // mix into path hash
    struct hash_data data;
    data.prev_hash = this->path_hash;
    data.src_addr = src_addr;
    data.dst_addr = dst_addr;
    path_hash_t out;
    MurmurHash3_x64_128(&data, sizeof(data), 0 /* seed */, &out);
    this->path_hash = out;
}

void CoverageTracker::Cover(uintptr_t addr)
{
    this->Cover(addr, addr);
}

uint32_t CoverageTracker::Popcount()
{
    uint32_t ret = 0;
    for (size_t i=0; i < num_bytes_to_alloc; i++)
    {
        // todo: do some loop unrolling here
        if (this->covmap[i] != 0)
        {
            ret++;
        }
    }
    return ret;
}

uint64_t CoverageTracker::Total()
{
    return this->total;
}

void CoverageTracker::Clear()
{
    memset(this->covmap, 0, num_bytes_to_alloc);
}


void CoverageTracker::Union(CoverageTracker *other)
{
    for (size_t i=0; i < num_bytes_to_alloc; i++)
    {
        this->covmap[i] = std::max(this->covmap[i], other->covmap[i]);
    }
    this->total = std::max(this->total, other->total);
}

bool CoverageTracker::HasNewPath(CoverageTracker *other)
{
    // Check if `other` has ANY more coverage
    for (size_t i=0; i < num_bytes_to_alloc; i++)
    {
        if (other->covmap[i] > this->covmap[i])
        {
            return true;
        }
    }
    return false;
}

bool CoverageTracker::MaximizesEdge(CoverageTracker *other) const
{
    for (size_t i=0; i < num_bytes_to_alloc; i++)
    {
        if (this->covmap[i] != 0 && other->covmap[i] >= this->covmap[i])
        {
            return true;
        }
    }
}

}
}