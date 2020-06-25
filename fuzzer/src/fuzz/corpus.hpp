// corpus.hpp
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Maintains a corpus of strings to match against.
//

#pragma once

#include <cstdint>
#include <vector>

#include "coverage-tracker.hpp"


namespace regulator
{
namespace fuzz
{

/**
 * A single entry in the corpus, ie, a string.
 * Also contains some meta-information about past
 * executions against this string.
 */
class CorpusEntry
{
public:
    /**
     * Construct a CorpusEntry by deep-copying the given structures.
     */
    CorpusEntry(const uint8_t *buf, size_t buflen, uint64_t opcount, CoverageTracker *coverage_tracker);

    ~CorpusEntry();

    /**
     * A generic heuristic derived from internal state.
     * 
     * Generally, higher goodness = more desirable
     */
    uint64_t Goodness();

    uint8_t *buf;
    uint32_t buflen;
    uint64_t opcount;
    CoverageTracker *coverage_tracker;
};


/**
 * Contains the entire corpus of fuzz inputs and their known effects
 */
class Corpus
{
public:
    Corpus();
    ~Corpus();

    /**
     * Store the results of a run into the corpus.
     * Ownership of the `entry` object is transferred to the Corpus.
     */
    void Record(CorpusEntry *entry);

    /**
     * Get one CorpusEntry arbitrarily.
     * 
     * NOTE: DO NOT MODIFY RETURN VALUE
     */
    CorpusEntry *GetOne();


    /**
     * Gets the ith entry.
     * 
     * Returns nullptr when out of bounds.
     * 
     * NOTE: DO NOT MODIFY RETURN VALUE
     */
    CorpusEntry *Get(size_t i);

    /**
     * Gets the maximum opcount known in this corpus
     */
    uint64_t MaxOpcount();

    /**
     * Gets the corpus entry with the highest Goodness measure
     */
    CorpusEntry *MostGood();

    /**
     * The number of entries in the corpus
     */
    size_t Size() const;

    static const size_t MaxEntries;
private:
    /**
     * Remove one CorpusEntry, used to make room for another.
     */
    void EvictOne();

    /**
     * Adds one CorpusEntry to the heap. Performs no bounds checks
     * on heap size.
     */
    void Add(CorpusEntry *entry);

    CoverageTracker *coverage_upper_bound;

    /**
     * Min-Heap of CorpusEntries as measured by
     * CoverageTracker's Popcount().
     */
    std::vector<CorpusEntry*> min_heap;

    uint32_t max_corpus_size;
};

}
}