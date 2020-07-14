// work-queue.hpp
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Contains a WorkQueue class which holds information about
// an in-progress fuzzing generation pass.

#pragma once

#include <vector>

#include "corpus.hpp"

template<typename Char>
class Queue
{
public:
    Queue();
    ~Queue();
private:
    std::vector<CorpusEntry *> work_queue;
};

