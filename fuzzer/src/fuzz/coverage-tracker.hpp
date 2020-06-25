// coverage-tracker.hpp
//
// contains an AFL-style code coverage tracker

#pragma once

#include <cstdint>

namespace regulator
{
namespace fuzz
{

/**
 * The number of pc address (least-significant) bits to use.
 */
const uint32_t MAX_CODE_SIZE = 16;

/**
 * A bitmask for post-shift addresses
 */
constexpr uint32_t CODE_MASK = (1 << MAX_CODE_SIZE) - 1;


#define REGULATOR_FUZZ_TRANSFORM_ADDR(x) ((static_cast<uint32_t>(x) >> 3) & CODE_MASK)


/**
 * AFL-style coverage tracker.
 * 
 * Coverage is approximate. It is assumed that program
 * counters must be a multiple of 8.
 */
class CoverageTracker {
public:
    CoverageTracker();
    CoverageTracker(const CoverageTracker &other);
    ~CoverageTracker();

    /**
     * Mark a branch from src_addr to dst_addr as covered
     */
    void Cover(uintptr_t src_addr, uintptr_t dst_addr);

    /**
     * Raw population count of the bitfield members. This is
     * roughly correlated with the total coverage.
     */
    uint32_t Popcount();

    /**
     * Add coverage path info from `other` into this coverage
     * tracker.
     */
    void Union(CoverageTracker *other);

    /**
     * Returns true if `other` contains any branch transitions
     * not found in `this`.
     */
    bool HasNewPath(CoverageTracker *other);

    /**
     * Resets tracker
     */
    void Clear();

private:
    uint8_t *bitfield;
};

}
}
