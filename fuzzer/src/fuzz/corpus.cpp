#include "corpus.hpp"

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
CorpusEntry<Char> *Corpus<Char>::GetOne()
{
    if (this->Size() < 1)
    {
        return nullptr;
    }
    
    return this->Get(random() % this->Size());
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

    return this->coverage_upper_bound->MaximizesEdge(coverage_tracker);
}


template<typename Char>
bool Corpus<Char>::HasNewPath(CoverageTracker *coverage_tracker)
{
    return this->coverage_upper_bound->HasNewPath(coverage_tracker);
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
