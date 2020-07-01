// corpus.hpp
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Maintains a corpus of strings to match against.
//

#pragma once

#include <cstdint>
#include <vector>
#include <string>


#include "coverage-tracker.hpp"


namespace regulator
{
namespace fuzz
{

// The number of hashtable slots to have for tracking corpus
// entry path hashes.
//
// Keep a multiple of 2.
const size_t CORPUS_PATH_HASHTABLE_SIZE = 1024;

/**
 * A single entry in the corpus, ie, a string.
 * Also contains some meta-information about past
 * executions against this string.
 */
class CorpusEntry
{
public:
    /**
     * Construct a CorpusEntry
     * Takes ownership of the params.
     */
    CorpusEntry(uint8_t *buf, size_t buflen, CoverageTracker *coverage_tracker);

    ~CorpusEntry();

    inline CoverageTracker *GetCoverageTracker()
    {
        return this->coverage_tracker;
    };

    std::string ToString() const;

    uint8_t *buf;
    uint32_t buflen;
    regulator::fuzz::CoverageTracker *coverage_tracker;
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
     * Gets the maximum opcount entry known in this corpus
     */
    CorpusEntry *MaxOpcount();

    /**
     * Returns True if this tracker object has any cfg edges which
     * maximize the current known upper bound
     */
    bool MaximizesUpperBound(CoverageTracker *coverage_tracker);


    /**
     * Returns True if this tracker object exceeds the known upper bound
     */
    bool HasNewPath(CoverageTracker *coverage_tracker);

    /**
     * Removes corpus members which are probably redundant
     */
    void Economize();


    /**
     * Returns true if we likely already have an entry
     * in the corpus for the given execution's trace.
     */
    bool IsRedundant(CoverageTracker *coverage_tracker) const;


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

    std::vector<CorpusEntry*> entries;

    std::vector<uint32_t> hashtable[CORPUS_PATH_HASHTABLE_SIZE];
};

}
}
