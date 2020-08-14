#include "corpus.hpp"
#include "coverage-tracker.hpp"
#include "mutations.hpp"

#include <cstring>
#include <vector>
#include <random>
#include <iostream>
#include <iomanip>
#include <sstream>

namespace regulator
{
namespace fuzz
{

/**
 * The maximum number of suggestions to follow
 * while generating children.
 */
static const size_t MAX_SUGGESTIONS = 10;

template <typename Char>
CorpusEntry<Char>::CorpusEntry(
    Char *buf,
    size_t buflen,
    CoverageTracker *coverage_tracker)
{
    this->buflen = buflen;
    this->buf = buf;
    this->coverage_tracker = coverage_tracker;
}


template <typename Char>
CorpusEntry<Char>::CorpusEntry(CorpusEntry<Char> &other)
{
    this->buflen = other.buflen;
    this->buf = new Char[other.buflen];
    memcpy(this->buf, other.buf, other.buflen * sizeof(Char));
    this->coverage_tracker = new CoverageTracker(*other.coverage_tracker);
}


template <typename Char>
CorpusEntry<Char>::~CorpusEntry()
{
    delete[] this->buf;
    delete this->coverage_tracker;
}


template <typename Char>
std::string CorpusEntry<Char>::ToString() const
{
    std::ostringstream out;
    out << "<CorpusEntry @0x" << std::hex << (uintptr_t)(this);
    out << std::dec << " ";

    out << "width=" << sizeof(Char) << " ";

    out << " word=\"";
    for (size_t i = 0; i < this->buflen; i++)
    {
        Char c = this->buf[i];
        if ('\\' == c)
        {
            out << "\\\\";
        }
        else if (' ' <= c && c <= '~')
        {
            out << static_cast<char>(c);
        }
        else if (c == '\n')
        {
            out << "\\n";
        }
        else if (c == '\t')
        {
            out << "\\t";
        }
        else if (c == '\r')
        {
            out << "\\r";
        }
        else
        {
            out << "\\x";
            out << std::setw(sizeof(Char) * 2) << std::setfill('0') << std::hex
                << static_cast<uint32_t>(c);
            out << std::dec << std::setw(0) << std::setfill(' ');
        }
    }
    out << std::dec;
    out << "\" Total=" << this->coverage_tracker->Total();

    // shorten path hash into 32 bits (from 128) by XOR-ing the parts
    path_hash_t hash = this->coverage_tracker->PathHash();
    uint32_t hash_out = 0;
    hash_out ^= hash & (0xFFFFFFFF);
    hash >>= 32;
    hash_out ^= hash & (0xFFFFFFFF);
    hash >>= 32;
    hash_out ^= hash & (0xFFFFFFFF);
    hash >>= 32;
    hash_out ^= hash & (0xFFFFFFFF);

    out << " PathHash=" << std::hex << hash_out;
    out << ">";

    return out.str();
}


template<typename Char>
size_t CorpusEntry<Char>::MemoryFootprint() const
{
    return sizeof(CorpusEntry) + sizeof(Char) * this->buflen + this->coverage_tracker->MemoryFootprint();
}


template<typename Char>
Corpus<Char>::Corpus()
{
    this->coverage_upper_bound = new CoverageTracker();
    this->maximizing_entry = nullptr;
    this->extra_interesting = new std::vector<Char>();
    memset(this->staleness, 0, sizeof(this->staleness));
}


template<typename Char>
Corpus<Char>::~Corpus()
{
    while (this->new_entries.size() > 0)
    {
        delete this->new_entries.at(this->new_entries.size() - 1);
        this->new_entries.pop_back();
    }

    while (this->flushed_entries.size() > 0)
    {
        delete this->flushed_entries.at(this->flushed_entries.size() - 1);
        this->flushed_entries.pop_back();
    }

    delete this->coverage_upper_bound;
    delete this->maximizing_entry;
    delete this->extra_interesting;
}


template<typename Char>
void Corpus<Char>::Record(CorpusEntry<Char> *entry)
{
    this->new_entries.push_back(entry);

    if (this->maximizing_entry == nullptr ||
        this->maximizing_entry->GetCoverageTracker()->Total() < entry->GetCoverageTracker()->Total())
    {
        // this is the new maximizing entry
        delete this->maximizing_entry;
        this->maximizing_entry = new CorpusEntry<Char>(*entry);
    }
}


template<typename Char>
void Corpus<Char>::Add(CorpusEntry<Char> *entry)
{
    this->flushed_entries.push_back(entry);

    // Reset staleness for any edges which were just exceeded
    for (size_t i=0; i<MAP_SIZE; i++)
    {
        if (entry->GetCoverageTracker()->EdgeIsGreater(this->coverage_upper_bound, i))
        {
            this->staleness[i] = 0;
        }
    }

    this->coverage_upper_bound->Union(entry->coverage_tracker);

    // Record the path hash in the hashtable

    path_hash_t path_hash = entry->coverage_tracker->PathHash();
    size_t hashtable_slot = static_cast<path_hash_t>(path_hash & (CORPUS_PATH_HASHTABLE_SIZE - 1));

    auto slot = &(this->hashtable[hashtable_slot]);
    for (size_t i=0; i<slot->size(); i++)
    {
        if (slot->at(i) == path_hash)
        {
            goto already_seen_hash;
        }
    }

    // hash has not been seen before, so append
    slot->push_back(path_hash);

    already_seen_hash:
    // do not add the hash a second time
    ;
}


template<typename Char>
bool Corpus<Char>::IsRedundant(CoverageTracker *coverage_tracker) const
{
    path_hash_t path_hash = coverage_tracker->PathHash();
    size_t hashtable_slot = static_cast<size_t>(path_hash & (CORPUS_PATH_HASHTABLE_SIZE - 1));

    auto slot = &(this->hashtable[hashtable_slot]);
    for (size_t i=0; i<slot->size(); i++)
    {
        if (slot->at(i) == path_hash)
        {
            return true;
        }
    }
    return false;
}


template<typename Char>
void Corpus<Char>::GenerateChildren(
    const CorpusEntry<Char> *parent,
    size_t n_children,
    std::vector<Char *> &out
)
{
    // NOTE: for PerfFuzz, each child is a mutation OF THE PREVIOUS GENERATED CHILD
    // ... but I've commented that bit out below
    const Char *last_buf = parent->buf;
    size_t buflen = parent->buflen;

    // Get the mutation suggestions
    // std::vector<struct suggestion> suggestions;
    // parent->coverage_tracker->GetSuggestions(
    //     suggestions
    // );

    // // Shuffle the suggestions using a Fisher-Yates shuffle
    // // BUT stop after the first MAX_SUGGESTIONS slots
    // for (size_t i=0; i + 2 <= std::min(MAX_SUGGESTIONS, suggestions.size()); i++)
    // {
    //     size_t j = (static_cast<size_t>(random()) % (suggestions.size() - i)) + i;
    //     struct suggestion tmp = suggestions[i];
    //     suggestions[i] = suggestions[j];
    //     suggestions[j] = tmp;
    // }

    // for (size_t i=0; i < std::min(MAX_SUGGESTIONS, suggestions.size()); i++)
    // {
    //     Char *newbuf = new Char[buflen];
    //     memcpy(newbuf, parent->buf, buflen * sizeof(Char));
    //     take_a_suggestion(newbuf, buflen, suggestions[i]);
    //     out.push_back(newbuf);
    //     n_children--;
    // }

    for (size_t i = 0; i < n_children; i++)
    {
        Char *newbuf = new Char[buflen];
        memcpy(newbuf, last_buf, buflen * sizeof(Char));

        // select a mutation to apply
        switch (random() % 16)
        {
        case 0:
            mutate_random_char(newbuf, buflen);
            break;
        case 1:
        case 2:
            arith_random_char(newbuf, buflen);
            break;
        case 3:
        case 4:
            swap_random_char(newbuf, buflen);
            break;
        case 6:
        case 7:
            crossover(newbuf, buflen, this->GetCoparent());
            break;
        case 8:
        case 9:
            duplicate_subsequence(newbuf, buflen);
            break;
        case 10:
        case 11:
        case 12:
        case 13:
            replace_with_special(newbuf, buflen, *this->extra_interesting);
            break;
        case 5:
        case 14:
        case 15:
            rotate_once(newbuf, buflen);
            break;
        default:
            throw "Unreachable";
        }

        // last_buf = newbuf;
        out.push_back(newbuf);
    }
}

template<typename Char>
CorpusEntry<Char> *Corpus<Char>::Get(size_t i)
{
    if (i >= this->flushed_entries.size())
    {
        return nullptr;
    }

    return this->flushed_entries[i];
}


template<typename Char>
void Corpus<Char>::BumpStaleness(CoverageTracker *coverage_tracker)
{
    for (size_t i=0; i < MAP_SIZE; i++)
    {
        if  (
                this->staleness[i] < UINT32_MAX &&
                coverage_tracker->EdgeIsEqual(this->coverage_upper_bound, i)
            )
        {
            // NOTE: we don't need to reset staleness to 0 upon exceeding the upper
            // bound here, that will be done at flush-time, below.
            this->staleness[i]++;
        }
    }
}


template<typename Char>
size_t Corpus<Char>::GetStalenessScore(CoverageTracker *coverage_tracker)
{
    // Maximum staleness seen across all components
    // = 1 to avoid div-by-zero when staleness is in initial state (all zero)
    uint32_t global_max_staleness = 1;

    // Minimum staleness seen across all components
    uint32_t global_min_staleness = UINT32_MAX;

    // Minimum staleness seen on a component maximized by `coverage_tracker`
    uint32_t my_min_staleness = UINT32_MAX;

    for (size_t i=0; i < MAP_SIZE; i++)
    {
        if (this->coverage_upper_bound->EdgeIsCovered(i))
        {
            global_max_staleness = std::max(global_max_staleness, this->staleness[i]);
            global_min_staleness = std::min(global_min_staleness, this->staleness[i]);

            if (this->coverage_upper_bound->EdgeIsEqual(coverage_tracker, i))
            {
                // the entry maximizes this upper bound
                my_min_staleness = std::min(my_min_staleness, this->staleness[i]);
            }
        }
    }

    // This can occur if the entry is not maximizing -- staleness has no practical meaning,
    // so just set this here
    my_min_staleness = std::min(my_min_staleness, global_min_staleness);

    return (MAX_STALENESS_SCORE * (my_min_staleness - global_min_staleness)) / global_max_staleness;
}


template<typename Char>
CorpusEntry<Char> *Corpus<Char>::MaxOpcount()
{
    return this->maximizing_entry;
}


template<typename Char>
bool Corpus<Char>::MaximizesUpperBound(CoverageTracker *coverage_tracker)
{
    if (coverage_tracker == nullptr)
    {
        return false;
    }

    return this->coverage_upper_bound->MaximizesAnyEdge(coverage_tracker);
}


template<typename Char>
bool Corpus<Char>::HasNewPath(CoverageTracker *coverage_tracker)
{
    return this->coverage_upper_bound->HasNewPath(coverage_tracker);
}

template<typename Char>
bool Corpus<Char>::MaximizesEdge(CoverageTracker *coverage_tracker, size_t edge_idx) const
{
    return this->coverage_upper_bound->EdgeIsEqual(coverage_tracker, edge_idx);
}

template<typename Char>
void Corpus<Char>::FlushGeneration()
{
    for (size_t i=0; i<this->new_entries.size(); i++)
    {
        CorpusEntry<Char> *entry = this->new_entries[i];

        if (!this->IsRedundant(entry->GetCoverageTracker()))
        {
            this->Add(entry);
        }
        else
        {
            delete entry;
        }
    }

    this->new_entries.clear();
}


template<typename Char>
size_t Corpus<Char>::MemoryFootprint() const
{
    size_t ret = 0;
    ret += sizeof(Corpus);
    ret += this->coverage_upper_bound->MemoryFootprint();

    for (size_t i=0; i<this->new_entries.size(); i++)
    {
        ret += this->new_entries[i]->MemoryFootprint();
    }

    for (size_t i=0; i<this->flushed_entries.size(); i++)
    {
        ret += this->flushed_entries[i]->MemoryFootprint();
    }

    for (size_t i=0; i<CORPUS_PATH_HASHTABLE_SIZE; i++)
    {
        ret += this->hashtable[i].size() * sizeof(this->hashtable[i]) + sizeof(this->hashtable[i][0]);
    }

    return ret;
}

template<typename Char>
inline void Corpus<Char>::SetInteresting(std::vector<Char> *interesting)
{
    delete this->extra_interesting;
    this->extra_interesting = interesting;
}

template<typename Char>
const Char * const Corpus<Char>::GetCoparent() const
{
    size_t coparent_idx = static_cast<size_t>(random()) % (this->flushed_entries.size());
    const CorpusEntry<Char> *coparent = this->flushed_entries[coparent_idx];

    return coparent->buf;
}

template<typename Char>
double Corpus<Char>::Residency() const
{
    return this->coverage_upper_bound->Residency();
}


template<typename Char>
size_t Corpus<Char>::Size() const
{
    return this->flushed_entries.size();
}


// Specialization
template class CorpusEntry<uint8_t>;
template class CorpusEntry<uint16_t>;
template class Corpus<uint8_t>;
template class Corpus<uint16_t>;

}
}
