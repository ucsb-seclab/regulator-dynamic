// work-queue.hpp
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Contains a WorkQueue class which holds information about
// an in-progress fuzzing generation pass.

#pragma once

#include <vector>

#include "corpus.hpp"
#include "coverage-tracker.hpp"

namespace regulator
{
namespace fuzz
{
template<typename Char>
class Queue
{
public:
    Queue();
    ~Queue();

    /**
     * Refills the queue based on the given corpus.
     * 
     * Makes use of various heuristics, etc.
     * 
     * NOTE: does not take ownership of the corpus or corpus
     * entries
     */
    void Fill(Corpus<Char> *corpus);

    /**
     * Returns true if the queue is not yet emptied
     */
    bool HasNext() const;

    /**
     * Pops the next queue entry
     */
    CorpusEntry<Char> *Pop();

private:
    std::vector<CorpusEntry<Char> *> queue;
};

}
}

