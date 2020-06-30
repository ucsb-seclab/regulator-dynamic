#include "corpus.hpp"

#include <cstring>
#include <vector>
#include <random>
#include <iostream>
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

CorpusEntry::~CorpusEntry()
{
    delete[] this->buf;
    delete this->coverage_tracker;
}

std::string CorpusEntry::ToString() const
{
    std::ostringstream out;
    out << "<CorpusEntry ";
    out << "word=\"";
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
            out.width(2);
            out.fill('0');
            out << "\\x" << std::hex << static_cast<unsigned char>(c);
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
}

CorpusEntry *Corpus::GetOne()
{
    if (this->entries.size() < 1)
    {
        return nullptr;
    }
    
    return this->entries[random() % this->entries.size()];
}

CorpusEntry *Corpus::Get(size_t i)
{
    if (i >= this->entries.size())
    {
        return nullptr;
    }

    return this->entries[i];
}

CorpusEntry *Corpus::MaxOpcount()
{
    if (this->entries.size() < 1)
    {
        return nullptr;
    }

    CorpusEntry *most = this->entries[0];
    for (size_t i=1; i<this->entries.size(); i++)
    {
        if (most->coverage_tracker->Total() < this->entries[i]->coverage_tracker->Total())
        {
            most = this->entries[i];
        }
    }
    return most;
}

bool Corpus::MaximizesUpperBound(CoverageTracker *coverage_tracker)
{
    return this->coverage_upper_bound->MaximizesEdge(coverage_tracker);
}

bool Corpus::HasNewPath(CoverageTracker *coverage_tracker)
{
    return this->coverage_upper_bound->HasNewPath(coverage_tracker);
}

void Corpus::Economize()
{
    // naive implementation -- eliminate anything w/ duplicate hashes
    std::vector<CorpusEntry *> not_redundant;

    for (size_t i=0; i<this->entries.size(); i++)
    {
        CorpusEntry *left = this->entries[i];

        for (size_t j=i+1; j < this->entries.size(); j++)
        {
            CorpusEntry *right = this->entries[i];
            if (left->GetCoverageTracker()->IsEquivalent(right->GetCoverageTracker()))
            {
                goto redundant;
            }
        }

        // no redundancy noticed
        not_redundant.push_back(left);

        // fall-through / jump to outer loop
        redundant:
        continue;
    }

    this->entries.clear();
    this->entries.insert(this->entries.begin(), not_redundant.begin(), not_redundant.end());
}

size_t Corpus::Size() const
{
    return this->entries.size();
}

void Corpus::EvictOne()
{
    throw "NotImplemented";
}

}
}