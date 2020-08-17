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
#include "mutations.hpp"


namespace regulator
{
namespace fuzz
{

// The number of hashtable slots to have for tracking corpus
// entry path hashes.
//
// Keep a multiple of 2.
const size_t CORPUS_PATH_HASHTABLE_SIZE = 4096;


// The maximum staleness score achievable by an entry
const uint32_t MAX_STALENESS_SCORE = 4096;

/**
 * A single entry in the corpus, ie, a string.
 * Also contains some meta-information about past
 * executions against this string.
 */
template <typename Char>
class CorpusEntry
{
public:
    /**
     * Construct a CorpusEntry
     * Takes ownership of the params.
     */
    CorpusEntry(Char *buf, size_t buflen, CoverageTracker *coverage_tracker);
    CorpusEntry(CorpusEntry<Char> &other);

    ~CorpusEntry();

    inline CoverageTracker *GetCoverageTracker()
    {
        return this->coverage_tracker;
    };

    std::string ToString() const;

    Char *buf;
    size_t buflen;
    regulator::fuzz::CoverageTracker *coverage_tracker;
};


/**
 * Contains the entire corpus of fuzz inputs and their known effects
 */
template <typename Char>
class Corpus
{
public:
    Corpus();
    ~Corpus();

    /**
     * Store the results of a run into the corpus.
     * Ownership of the `entry` object is transferred to the Corpus.
     * 
     * NOTE: This will not increase the corpus Size() until
     *       FlushGeneration() is called.
     */
    void Record(CorpusEntry<Char> *entry);

    /**
     * Generate children from the given parent byte pattern.
     */
    void GenerateChildren(
        const CorpusEntry<Char> *parent,
        size_t n_children,
        std::vector<Char *> &out
    );

    /**
     * Gets the ith entry.
     * 
     * Returns nullptr when out of bounds.
     * 
     * NOTE: DO NOT MODIFY RETURN VALUE
     */
    CorpusEntry<Char> *Get(size_t i);

    /**
     * After an execution of the regexp, bump the internal staleness
     * map according to observed coverage from the run.
     */
    void BumpStaleness(CoverageTracker *coverage_tracker);

    /**
     * Get a heuristic measure of how 'stale' this execution's coverage
     * trace is.
     * 
     * Higher return value = more stale.
     * Seel also: MAX_STALENESS_SCORE
     */
    size_t GetStalenessScore(CoverageTracker *coverage_tracker);

    /**
     * Gets the maximum opcount entry known in this corpus
     */
    CorpusEntry<Char> *MaxOpcount();

    /**
     * Returns true if this tracker object has any cfg edges which
     * maximize the current known upper bound
     */
    bool MaximizesUpperBound(CoverageTracker *coverage_tracker);

    /**
     * Returns True if this tracker object exceeds the known upper bound.
     * 
     * NOTE: non-flushed entries do not impact the path upper bound
     */
    bool HasNewPath(CoverageTracker *coverage_tracker);

    /**
     * Returns True if this tracker object maximizes the known upper
     * bound of executions at the given edge index
     */
    bool MaximizesEdge(CoverageTracker *coverage_tracker, size_t edge_idx) const;

    /**
     * Mark the current generation sweep as complete. Flushes the pending,
     * non-redundant entries.
     */
    void FlushGeneration();

    /**
     * Returns true if we likely already have an entry
     * in the corpus for the given execution's trace.
     */
    bool IsRedundant(CoverageTracker *coverage_tracker) const;

    /**
     * Set the "interesting characters" to use during mutation.
     * 
     * Takes ownership of the vector.
     */
    void SetInteresting(std::vector<Char> *interesting);

    /**
     * Gets the percentage of slots which are non-zero in the
     * upper-bound coverage map.
     * 
     * Returns a number between 0 and 1, inclusive.
     */
    double Residency() const;

    /**
     * The number of flushed entries in the corpus
     */
    size_t Size() const;

private:

    /**
     * Get an arbitrary buffer from the corpus to use as a coparent
     * 
     * NOTE: DO NOT MOIDIFY THE COPARENT
     */
    const Char * const GetCoparent() const;

    /**
     * Adds one CorpusEntry to the heap. Performs no bounds checks
     * on heap size.
     */
    void Add(CorpusEntry<Char> *entry);

    CoverageTracker *coverage_upper_bound;

    /**
     * The entry with the highest-known Total()
     */
    CorpusEntry<Char> *maximizing_entry;

    /**
     * Entries which are recorded for a current generation
     * but not yet flushed because the generation has not
     * completed
     */
    std::vector<CorpusEntry<Char> *> new_entries;

    /**
     * A buffer of randomly-selected coparents
     */
    std::vector<Char *> coparent_buffer;

    /**
     * Some supplementary interesting chars to use for mutations
     */
    std::vector<Char> *extra_interesting;

    /**
     * Records all entries which have been economized
     */
    std::vector<CorpusEntry<Char> *> flushed_entries;

    std::vector<path_hash_t> hashtable[CORPUS_PATH_HASHTABLE_SIZE];

    /**
     * A record of how "stale" each component is
     */
    uint32_t staleness[MAP_SIZE];
};

}
}
