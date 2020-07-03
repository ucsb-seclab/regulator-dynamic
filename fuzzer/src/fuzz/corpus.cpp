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

CorpusEntry::CorpusEntry(
    uint8_t *buf,
    size_t buflen,
    CoverageTracker *coverage_tracker)
{
    this->buflen = buflen;
    this->buf = buf;
    this->coverage_tracker = coverage_tracker;
}

CorpusEntry::CorpusEntry(CorpusEntry &other)
{
    this->buflen = other.buflen;
    this->buf = new uint8_t[other.buflen];
    memcpy(this->buf, other.buf, other.buflen);
    this->coverage_tracker = new CoverageTracker(*other.coverage_tracker);
}

CorpusEntry::~CorpusEntry()
{
    delete[] this->buf;
    delete this->coverage_tracker;
}

std::string CorpusEntry::ToString() const
{
    std::ostringstream out;
    out << "<CorpusEntry @0x" << std::hex << (uintptr_t)(this);
    out << std::dec;
    out << " word=\"";
    for (size_t i = 0; i < this->buflen; i++)
    {
        char c = this->buf[i];
        if (' ' <= c && c <= '~')
        {
            out << c;
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
            out << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint16_t>(c);
            out << std::dec << std::setw(0);
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


size_t CorpusEntry::MemoryFootprint() const
{
    return sizeof(CorpusEntry) + sizeof(*buf) * this->buflen + this->coverage_tracker->MemoryFootprint();
}


Corpus::Corpus()
{
    this->coverage_upper_bound = new CoverageTracker();
}

Corpus::~Corpus()
{
    while (this->entries.size() > 0)
    {
        delete this->entries.at(this->entries.size() - 1);
        this->entries.pop_back();
    }

    while (this->economized_entries.size() > 0)
    {
        delete this->economized_entries.at(this->economized_entries.size() - 1);
        this->entries.pop_back();
    }

    delete this->coverage_upper_bound;
}

void Corpus::Record(CorpusEntry *entry)
{
    this->Add(entry);
}

void Corpus::Add(CorpusEntry *entry)
{
    this->entries.push_back(entry);

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

bool Corpus::IsRedundant(CoverageTracker *coverage_tracker) const
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

CorpusEntry *Corpus::GetOne()
{
    if (this->Size() < 1)
    {
        return nullptr;
    }
    
    return this->Get(random() % this->Size());
}

CorpusEntry *Corpus::Get(size_t i)
{
    if (i >= this->Size())
    {
        return nullptr;
    }

    if (i <= this->entries.size())
    {
        return this->entries[i];
    }

    return this->economized_entries[i - this->entries.size()];
}

CorpusEntry *Corpus::MaxOpcount()
{
    if (this->Size() < 1)
    {
        return nullptr;
    }

    CorpusEntry *most = this->Get(0);
    for (size_t i=1; i<this->Size(); i++)
    {
        if (most->coverage_tracker->Total() < this->Get(i)->coverage_tracker->Total())
        {
            most = this->Get(i);
        }
    }
    return most;
}

bool Corpus::MaximizesUpperBound(CoverageTracker *coverage_tracker)
{
    if (coverage_tracker == nullptr)
    {
        return false;
    }

    return this->coverage_upper_bound->MaximizesEdge(coverage_tracker);
}

bool Corpus::HasNewPath(CoverageTracker *coverage_tracker)
{
    return this->coverage_upper_bound->HasNewPath(coverage_tracker);
}

void Corpus::Economize()
{
    // NOTE we make the assumption no CorpusEntry in `entries` has a hash
    // equal to a CorpusEntry in `economized_entries`

    // Create new hashtable for this procedure
    std::vector<path_hash_t> *tmp_hashtable = new std::vector<path_hash_t>[CORPUS_PATH_HASHTABLE_SIZE];

    // set everything as not-redundant
    bool *redundants = new bool[this->entries.size()];
    for (size_t i=0; i < this->entries.size(); i++)
    {
        redundants[i] = false;
    }

    for (size_t i=0; i<this->entries.size(); i++)
    {
        CorpusEntry *entry = this->entries[i];

        path_hash_t h = entry->GetCoverageTracker()->PathHash();

        auto slot = &(tmp_hashtable[h & (CORPUS_PATH_HASHTABLE_SIZE - 1)]);

        for (size_t j=0; j<slot->size(); j++)
        {
            if (slot->at(j) == h)
            {
                redundants[i] = true;
                goto known_redundant;
            }
        }

        slot->push_back(h);

        known_redundant:
        ;
    }

    for (size_t i=0; i<this->entries.size(); i++)
    {
        if (!redundants[i])
        {
            this->economized_entries.push_back(this->entries[i]);
        }
        else
        {
            delete this->entries[i];
        }
    }

    this->entries.clear();

    delete[] redundants;
    delete[] tmp_hashtable;
}

size_t Corpus::MemoryFootprint() const
{
    size_t ret = 0;
    ret += sizeof(Corpus);
    ret += this->coverage_upper_bound->MemoryFootprint();

    for (size_t i=0; i<this->entries.size(); i++)
    {
        ret += this->entries[i]->MemoryFootprint();
    }

    for (size_t i=0; i<this->economized_entries.size(); i++)
    {
        ret += this->economized_entries[i]->MemoryFootprint();
    }

    for (size_t i=0; i<CORPUS_PATH_HASHTABLE_SIZE; i++)
    {
        ret += this->hashtable[i].size() * sizeof(path_hash_t);
    }

    return ret;
}


double Corpus::Residency() const
{
    return this->coverage_upper_bound->Residency();
}


size_t Corpus::Size() const
{
    return this->entries.size() + this->economized_entries.size();
}

void Corpus::EvictOne()
{
    throw "NotImplemented";
}

}
}