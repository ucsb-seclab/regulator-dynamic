#include "work-queue.hpp"

#include <vector>
#include <random>
#include <iostream>

namespace regulator
{
namespace fuzz
{

template<typename Char>
Queue<Char>::Queue()
{
    // nothing to do
}

template<typename Char>
Queue<Char>::~Queue()
{
    // nothing to do
}

template<typename Char>
bool Queue<Char>::HasNext() const
{
    return this->queue.size() > 0;
}

template<typename Char>
CorpusEntry<Char> *Queue<Char>::Pop()
{
    CorpusEntry<Char> *ret = this->queue[this->queue.size() - 1];
    this->queue.pop_back();
    return ret;
}

template<typename Char>
void Queue<Char>::Fill(Corpus<Char> *corpus)
{
    // TODO this could be faster

    // Strategy:
    // 1. Create an array with all valid entry indices [0, 1, ... corpus.size() - 1]
    // 2. Shuffle the array
    // 3. Iterate over the array -- if entry at that index maximizes an edge
    //    which does not yet have a representative, then assign a representative
    // 4. Otherwise, with low probability, add the entry to the queue immediately.

    // A bitmap indicating which edges have already been assigned a representative
    uint8_t represented[MAP_SIZE];
    memset(represented, 0, MAP_SIZE);

    // Step 1: create map from array index to entry index
    size_t index_map_len = corpus->Size();
    size_t *index_map = new size_t[index_map_len];
    for (size_t i = 0; i < index_map_len; i++)
    {
        index_map[i] = i;
    }

    // Step 2: shuffle the index map (Fisher-Yates Shuffle)
    for (size_t i=0; i + 2 <= index_map_len; i++)
    {
        size_t j = (static_cast<size_t>(random()) % (index_map_len - i)) + i;
        size_t tmp = index_map[i];
        index_map[i] = index_map[j];
        index_map[j] = tmp;
    }

    // Step 3: iterate over index map
    for (size_t i=0; i < index_map_len; i++)
    {
        size_t corpus_entry_index = index_map[i];

        CorpusEntry<Char> *entry = corpus->Get(corpus_entry_index);
        bool already_selected = false;

        // iterate over each component in the perfmap to see if this entry
        // maximizes any components
        for (size_t j=0; j < MAP_SIZE && !already_selected; j++)
        {
            size_t rep_idx = j / 8;
            uint8_t rep_mask = static_cast<uint8_t>(1) << (j % 8);

            if ((represented[rep_idx] & rep_mask) == 0)
            {
                // this component is not represented, query to determine if
                // the entry is maximizing
                if (corpus->MaximizesEdge(entry->GetCoverageTracker(), j))
                {
                    // entry is maximizing, select it as a representative
                    this->queue.push_back(entry);
                    represented[rep_idx] |= rep_mask;
                    already_selected = true;

                    // mark all other components that this maximizes as represented
                    for (size_t k=j; k < MAP_SIZE; k++)
                    {
                        if (corpus->MaximizesEdge(entry->GetCoverageTracker(), k))
                        {
                            size_t rep_idx_second = k / 8;
                            uint8_t rep_mask_second = static_cast<uint8_t>(1) << (k % 8);
                            represented[rep_idx_second] |= rep_mask_second;
                        }
                    }
                }
            }
        }

        if (!already_selected)
        {
            uint32_t staleness_score = corpus->GetStalenessScore(entry->GetCoverageTracker());

            if ((random() % MAX_STALENESS_SCORE) >= std::max(staleness_score, MAX_STALENESS_SCORE - MAX_STALENESS_SCORE / 100))
            {
                // Item was selected
                this->queue.push_back(entry);
            }
        }

        // // Step 4: entry did not maximize any non-represented edges, with
        // // low probability (1%) add it to work-queue anyway

        // if (random() & (1024 - 1) <= 9) // (10 winners) / (1024 possible) ~= 1%
        // {
        //     // This entry was selected to be a parent
        //     this->queue.push_back(entry);
        // }

        entry_loop_out:
        ;
    }

    delete[] index_map;
}

template class Queue<uint8_t>;
template class Queue<uint16_t>;

}
}
