#include "corpus.hpp"

#include <cstring>
#include <vector>
#include <random>
#include <iostream>

namespace regulator
{
namespace fuzz
{

CorpusEntry::CorpusEntry(
    const uint8_t *buf,
    size_t buflen,
    uint64_t opcount,
    CoverageTracker *coverage_tracker)
{
    this->buflen = buflen;
    this->buf = new uint8_t[buflen];
    memcpy(this->buf, buf, buflen);
    this->coverage_tracker = coverage_tracker == nullptr ? new CoverageTracker() : new CoverageTracker(*coverage_tracker);
    this->opcount = opcount;
}

CorpusEntry::~CorpusEntry()
{
    delete[] this->buf;
    delete this->coverage_tracker;
}

uint64_t CorpusEntry::Goodness()
{
    // higher goodness = better

    uint64_t ret = 0;

    // add (scaled) popcount to goodness
    ret += 30 * this->coverage_tracker->Popcount();

    // add (scaled) opcount to goodness
    ret += this->opcount;

    return ret;
}

const size_t Corpus::MaxEntries = 16;

Corpus::Corpus()
{
    this->coverage_upper_bound = new CoverageTracker();
}

Corpus::~Corpus()
{
    while (this->min_heap.size() > 0)
    {
        delete this->min_heap.at(this->min_heap.size() - 1);
        this->min_heap.pop_back();
    }
    delete this->coverage_upper_bound;
}


void Corpus::Record(CorpusEntry *entry)
{
    // If this record demonstrates new covered branches then prefer to keep it
    // and evict another entry if necessary.
    bool should_add = (
        this->min_heap.size() == 0 ||
        this->coverage_upper_bound->HasNewPath(entry->coverage_tracker) ||
        (
            this->min_heap.size() < Corpus::MaxEntries &&
            this->min_heap[0]->Goodness() <= entry->Goodness()
        )
    );
    if (should_add)
    {
        if (this->min_heap.size() >= Corpus::MaxEntries)
        {
            this->EvictOne();
        }
        this->Add(entry);
        this->coverage_upper_bound->Union(entry->coverage_tracker);
    }
    else
    {
        // this record is useless... delete it
        delete entry;
    }
}

void Corpus::Add(CorpusEntry *entry)
{
    // add to the back of the heap and bubble up as appropriate
    this->min_heap.push_back(entry);

    // start bubbling
    size_t curr = this->min_heap.size() - 1;

    while (curr > 0)
    {
        size_t parent = (curr - 1) >> 1;
        if (this->min_heap[curr]->Goodness() < this->min_heap[parent]->Goodness())
        {
            // swap upward and continue
            CorpusEntry *tmp = this->min_heap[curr];
            this->min_heap[curr] = this->min_heap[parent];
            this->min_heap[parent] = tmp;
        }
        else
        {
            break;
        }
    }
}

CorpusEntry *Corpus::GetOne()
{
    if (this->min_heap.size() < 1)
    {
        return nullptr;
    }
    
    return this->min_heap[random() % this->min_heap.size()];
}

CorpusEntry *Corpus::Get(size_t i)
{
    if (i >= this->min_heap.size())
    {
        return nullptr;
    }

    return this->min_heap[i];
}

uint64_t Corpus::MaxOpcount()
{
    uint64_t ret = 0;
    for (size_t i=0; i<this->min_heap.size(); i++)
    {
        ret = std::max(ret, this->min_heap[i]->opcount);
    }
    return ret;
}

CorpusEntry *Corpus::MostGood()
{
    if (this->min_heap.size() == 0)
    {
        return nullptr;
    }

    CorpusEntry *ret = this->min_heap[0];
    for (size_t i=1; i < this->min_heap.size(); i++)
    {
        if (this->min_heap[i]->Goodness() > ret->Goodness())
        {
            ret = this->min_heap[i];
        }
    }

    return ret;
}

size_t Corpus::Size() const
{
    return this->min_heap.size();
}

void Corpus::EvictOne()
{
    // evict the least-good corpus member
    if (this->min_heap.size() == 0)
    {
        return;
    }

    // top-of-heap is index 0, which is 'least good'
    delete this->min_heap.at(0);

    // move last elem up to 0th index, then bubble it down into place
    this->min_heap[0] = this->min_heap[min_heap.size() - 1];
    this->min_heap.pop_back();

    // bubble down, visual aid:
    //     0
    //   1   2
    //  3 4 5 6
    #define CHILD_1_IDX(x) (2 * x + 1)
    #define CHILD_2_IDX(x) (2 * x + 2)

    size_t curr = 0;
    while (curr > 0)
    {
        size_t smallest = curr;
        if (this->min_heap[curr]->Goodness() > this->min_heap[CHILD_1_IDX(curr)]->Goodness())
        {
            smallest = CHILD_1_IDX(curr);
        }
        if (this->min_heap[smallest]->Goodness() > this->min_heap[CHILD_2_IDX(curr)]->Goodness())
        {
            smallest = CHILD_2_IDX(curr);
        }

        // if we have a new smallest then swap down and continue
        if (smallest != curr)
        {
            CorpusEntry *tmp = this->min_heap[curr];
            this->min_heap[curr] = this->min_heap[smallest];
            this->min_heap[smallest] = tmp;
            curr = smallest;
        }
        else // smallest == curr
        {
            break;
        }
    }

    #undef CHILD_1_IDX
    #undef CHILD_2_IDX
}

}
}