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

CoverageTracker::CoverageTracker(uint32_t string_length)
{
    this->string_length = string_length;
    this->covmap = new cov_t[MAP_SIZE];
    if (string_length == 0)
    {
        this->char_observation_counts = nullptr;
    }
    else
    {
        this->char_observation_counts = new uint16_t[string_length];
    }
    this->Clear();
}


CoverageTracker::CoverageTracker(const CoverageTracker &other)
{
    this->covmap = new cov_t[MAP_SIZE];
    memcpy(this->covmap, other.covmap, MAP_SIZE * sizeof(cov_t));
    if (other.string_length == 0 || other.char_observation_counts == nullptr)
    {
        this->char_observation_counts = nullptr;
    }
    else
    {
        this->char_observation_counts = new uint16_t[other.string_length];
        memcpy(this->char_observation_counts, other.char_observation_counts, other.string_length * sizeof(uint16_t));
    }
    this->total = other.total;
    this->path_hash = other.path_hash;
    this->suggestions = other.suggestions;
    this->string_length = other.string_length;
}


CoverageTracker::~CoverageTracker()
{
    delete[] this->covmap;
    delete[] this->char_observation_counts;
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
    const uint32_t byte_to_set = REGULATOR_FUZZ_TRANSFORM_ADDR(src_addr) ^
                                REGULATOR_FUZZ_TRANSFORM_ADDR(dst_addr);

    // protect from overflow by setting to MAX
    if (this->covmap[byte_to_set] < COV_MAX)
    {
        this->covmap[byte_to_set]++;
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
    this->path_hash = 0;
#if defined REG_COUNT_PATHLENGTH
    this->path_length = 0;
#endif
    this->total = 0;
    memset(this->covmap, 0, MAP_SIZE * sizeof(cov_t));
    if (this->char_observation_counts != nullptr)
    {
        memset(this->char_observation_counts, 0, this->string_length * sizeof(uint16_t));
    }
    this->suggestions.clear();
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

    for (size_t i=0; i<MAP_SIZE / sizeof(slot_ptr); i++)
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
    for (size_t i=0; i < MAP_SIZE; i++)
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
    for (size_t i=0; i < MAP_SIZE; i++)
    {
        if (other->covmap[i] > this->covmap[i])
        {
            return true;
        }
    }

    return false;
}

bool CoverageTracker::MaximizesAnyEdge(CoverageTracker *other) const
{
    for (size_t i=0; i < MAP_SIZE; i++)
    {
        if (this->covmap[i] != 0 && other->covmap[i] >= this->covmap[i])
        {
            return true;
        }
    }
    return false;
}

bool CoverageTracker::EdgeIsEqual(CoverageTracker *other, size_t edge_id) const
{
    return this->covmap[edge_id] == other->covmap[edge_id];
}

bool CoverageTracker::EdgeIsGreater(CoverageTracker *other, size_t edge_id) const
{
    return this->covmap[edge_id] > other->covmap[edge_id];
}

bool CoverageTracker::EdgeIsCovered(size_t edge_id) const
{
    return this->covmap[edge_id] > 0;
}

void CoverageTracker::Suggest(uintptr_t src, uintptr_t dst, uint16_t c, int pos)
{
    src *= 2;
    const uint32_t byte_to_set = REGULATOR_FUZZ_TRANSFORM_ADDR(src) ^
                            REGULATOR_FUZZ_TRANSFORM_ADDR(dst);

    // see if we already have a suggestion for this component
    for (size_t i=0; i < this->suggestions.size(); i++)
    {
        if (suggestions[i].component == byte_to_set)
        {
            return;
        }
    }

    struct suggestion sugg;
    sugg.c = c;
    sugg.pos = pos;
    sugg.component = byte_to_set;

    this->suggestions.push_back(sugg);
}

void CoverageTracker::GetSuggestions(std::vector<struct suggestion> &out) const
{
    for (size_t i=0; i < this->suggestions.size(); i++)
    {
        out.push_back(this->suggestions[i]);
    }
}

double CoverageTracker::Residency() const
{
    size_t num_occupied_slots = 0;
    for (size_t i=0; i < MAP_SIZE; i++)
    {
        // todo: do some loop unrolling here
        if (this->covmap[i] != 0)
        {
            num_occupied_slots++;
        }
    }

    return num_occupied_slots / static_cast<double>(MAP_SIZE);
}

void CoverageTracker::Observe(uint32_t i)
{
    if (this->char_observation_counts == nullptr)
    {
        return;
    }
    auto prev = this->char_observation_counts[i];
    this->char_observation_counts[i] = std::max((uint16_t)(prev + 1), prev);
}

uint16_t CoverageTracker::MaxObservation() const
{
    if (this->string_length == 0 || this->char_observation_counts == nullptr)
    {
        return 0;
    }
    auto max = this->char_observation_counts[0];
    for (size_t i = 1; i < this->string_length; i++)
    {
        max = std::max(this->char_observation_counts[i], max);
    }
    return max;
}

#if defined REG_COUNT_PATHLENGTH
uint64_t CoverageTracker::PathLength() const
{
    return this->path_length;
}

/**
 * Increment the path length count
 */
void CoverageTracker::IncPathLength()
{
    auto prev = this->path_length;
    this->path_length = std::max((uint64_t)(prev + 1), prev);
}
#endif

}
}
