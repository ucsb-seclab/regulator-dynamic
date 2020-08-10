// coverage-tracker.hpp
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Contains a code coverage tracker inspired by
// American Fuzzy Lop (AFL).
//
// This coverage tracker maintains an array of
// unsigned integers, traditionally called the
// "coverage map".
//
// The regular expression engine is instrumented
// such that upon execution of an instruction
// which has two or more successors, the engine
// calls CoverageTracker::Cover(src, dst), where
// `src` is the address of the branching statement,
// and `dst` is the address of the chosen successor.
//
// AFL also "bucketizes" the coverage map's cells,
// so that small variations in iteration count of
// loops don't throw off the generational heuristics.
// Calling CoverageTracker::Bucketize() will in-place
// modify the coverage map to replicate this behavior.
//
//

#pragma once

#include <cstdint>
#include <cstring>

namespace regulator
{
namespace fuzz
{

typedef __int128_t path_hash_t;

/**
 * Tracks coverage of a single cfg edge
 */
typedef uint8_t cov_t;


constexpr cov_t COV_MAX = ~static_cast<cov_t>(0);

/**
 * The number of pc address (least-significant) bits to use.
 */
const uint32_t MAX_CODE_SIZE = 14;

/**
 * A bitmask for post-shift addresses
 */
constexpr uint32_t CODE_MASK = (1 << MAX_CODE_SIZE) - 1;


#define REGULATOR_FUZZ_TRANSFORM_ADDR(x) ((static_cast<uint32_t>(x) >> 3) & CODE_MASK)


// NOTE: I believe this allocs one too many slots, but oh well.
// KEEP A MULTIPLE OF TWO
constexpr uint32_t MAP_SIZE = 1 << MAX_CODE_SIZE;


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
     * which maximizes (or exceeds) the known execution count of its
     * corresponding edge in `this`.
     */
    bool MaximizesAnyEdge(CoverageTracker *other) const;

    /**
     * Returns true if the edge `edge_id` has the same value
     * in both `this` and `other`.
     */
    bool EdgeIsEqual(CoverageTracker *other, size_t edge_id) const;

    /**
     * Returns true if the edge `edge_id` has explicitly more
     * hits in `this` than it does in `other`
     */
    bool EdgeIsGreater(CoverageTracker *other, size_t edge_id) const;

    /**
     * Returns true if the edge `edge_id` was covered in `this`
     * (ie has non-zero execution count).
     */
    bool EdgeIsCovered(size_t edge_id) const;

    /**
     * Simplifies the byte-map by putting each execution count
     * into one of several categories:
     * 
     * 0,
     * 1,
     * 2,
     * <= 4,
     * <= 8,
     * <= 16,
     * <= 32,
     * <= 127,
     * <= 256
     */
    void Bucketize();

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

    /**
     * Gets the number of bytes this object and its members
     * occupy in RAM.
     */
    size_t MemoryFootprint() const;

    /**
     * Gets the percentage of slots which are non-zero.
     * 
     * Returns a number between 0 and 1, inclusive.
     */
    double Residency() const;

private:
    cov_t *covmap;
    uint64_t total;
    path_hash_t path_hash;
    bool _deleted;
};

}
}
