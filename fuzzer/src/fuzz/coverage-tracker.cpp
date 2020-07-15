#include "coverage-tracker.hpp"

extern "C" {
    #include "murmur3.h"
}

#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstdlib>
#include <cstring>


namespace regulator
{
namespace fuzz
{

// NOTE: I believe this allocs one too many slots
// KEEP A MULTIPLE OF TWO
constexpr uint32_t num_slots_to_alloc = 1 << MAX_CODE_SIZE;

CoverageTracker::CoverageTracker()
{
    this->path_hash = 0;
    this->total = 0;
    this->covmap = new cov_t[num_slots_to_alloc];
    this->Clear();
    this->_deleted = false;
}

CoverageTracker::CoverageTracker(const CoverageTracker &other)
{
    this->total = other.total;
    this->covmap = new cov_t[num_slots_to_alloc];
    memcpy(this->covmap, other.covmap, num_slots_to_alloc * sizeof(cov_t));
    this->path_hash = other.path_hash;
    this->_deleted = false;
}


CoverageTracker::~CoverageTracker()
{
    if (this->_deleted)
    {
        std::cout << "DOUBLE FREE CoverageTracker" << std::endl;
    }
    this->_deleted = true;
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

    if (this->total < UINT64_MAX)
    {
        this->total++;
    }
    const uint32_t bit_to_set = REGULATOR_FUZZ_TRANSFORM_ADDR(src_addr) ^
                                REGULATOR_FUZZ_TRANSFORM_ADDR(dst_addr);

    // protect from overflow by setting to MAX
    if (this->covmap[bit_to_set] < COV_MAX)
    {
        this->covmap[bit_to_set]++;
    }

    // mix into path hash
    struct hash_data data;
    data.prev_hash = this->path_hash;
    data.src_addr = src_addr;
    data.dst_addr = dst_addr;
    path_hash_t out;
    MurmurHash3_x64_128(&data, sizeof(data), 0xDEADBEEF /* seed */, &out);
    this->path_hash = out;
}


void CoverageTracker::Cover(uintptr_t addr)
{
    this->Cover(addr, addr);
}


uint64_t CoverageTracker::Total()
{
    return this->total;
}

void CoverageTracker::Clear()
{
    memset(this->covmap, 0, num_slots_to_alloc * sizeof(cov_t));
    this->total = 0;
}

/**
 * bucketization lookup
 */
static const uint8_t count_class_lookup8[256] = {
    0,

    1,

    2,

    4,

    8,8,8,8,

    16,16,16,16,16,16,16,16,

    32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,

    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,

    128,128,128,128,128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
};

void CoverageTracker::Bucketize()
{
    uint64_t *slot_ptr = reinterpret_cast<uint64_t *>(this->covmap);
    uint8_t *curr;

    for (size_t i=0; i<num_slots_to_alloc / sizeof(slot_ptr); i++)
    {
        if (slot_ptr[i] != 0)
        {
            curr = reinterpret_cast<uint8_t *>(&slot_ptr[i]);
            curr[0] = count_class_lookup8[curr[0]];
            curr[1] = count_class_lookup8[curr[1]];
            curr[2] = count_class_lookup8[curr[2]];
            curr[3] = count_class_lookup8[curr[3]];
            curr[4] = count_class_lookup8[curr[4]];
            curr[5] = count_class_lookup8[curr[5]];
            curr[6] = count_class_lookup8[curr[6]];
            curr[7] = count_class_lookup8[curr[7]];
        }
    }
}

void CoverageTracker::Union(CoverageTracker *other)
{
    for (size_t i=0; i < num_slots_to_alloc; i++)
    {
        this->covmap[i] = std::max(this->covmap[i], other->covmap[i]);
    }
    this->total = std::max(this->total, other->total);
}

bool CoverageTracker::HasNewPath(CoverageTracker *other)
{
    // By the pigeonhole principle, if `other` has more total CFG
    // transitions then it MUST explore some new behavior
    if (other->Total() > this->Total())
    {
        return true;
    }

    // Check if `other` has ANY more coverage on an individual
    for (size_t i=0; i < num_slots_to_alloc; i++)
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
    for (size_t i=0; i < num_slots_to_alloc; i++)
    {
        if (this->covmap[i] != 0 && other->covmap[i] >= this->covmap[i])
        {
            return true;
        }
    }
}

size_t CoverageTracker::MemoryFootprint() const
{
    return sizeof(CoverageTracker) + sizeof(cov_t) * num_slots_to_alloc;
}


double CoverageTracker::Residency() const
{
    size_t num_occupied_slots = 0;
    for (size_t i=0; i < num_slots_to_alloc; i++)
    {
        // todo: do some loop unrolling here
        if (this->covmap[i] != 0)
        {
            num_occupied_slots++;
        }
    }

    return num_occupied_slots / static_cast<double>(num_slots_to_alloc);
}

}
}