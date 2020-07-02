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

typedef __int128_t path_hash_t;

/**
 * Tracks coverage of a single cfg edge
 */
typedef uint8_t cov_t;

constexpr cov_t COV_MAX = ~static_cast<cov_t>(0);

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
     * Mark a self-looping instruction as covered via
     * backward edge.
     */
    void Cover(uintptr_t addr);


    /**
     * Raw population count of the number of non-zero members. This is
     * roughly correlated with the total coverage.
     */
    uint32_t Popcount();

    /**
     * Counts the total number of edges traversed
     */
    uint64_t Total();

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
     * Returns true if `other` contains any branch transitions
     * which maximizes (or exceeds) the known execution count of an
     * edge in `this`.
     */
    bool MaximizesEdge(CoverageTracker *other) const;

    /**
     * Resets tracker
     */
    void Clear();

    /**
     * Returns true if `other` has the same path hash as this
     */
    inline bool IsEquivalent(CoverageTracker *other) const
    {
        return this->path_hash == other->path_hash;
    };

    /**
     * Gets the path hash
     */
    inline path_hash_t PathHash() const
    {
        return this->path_hash;
    };

private:
    cov_t *covmap;
    uint64_t total;
    path_hash_t path_hash;
};

}
}
