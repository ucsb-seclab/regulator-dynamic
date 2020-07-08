#include <iostream>
#include <vector>

#include "fuzz/corpus.hpp"
#include "fuzz/mutator.hpp"

#include "catch.hpp"

namespace f = regulator::fuzz;

template<typename Char>
inline void test_mutate_gens_unique()
{
    std::shared_ptr<f::Corpus<Char>> corp(new f::Corpus<Char>);
    
    // make TWO new CorpusEntries so we can ensure crossover
    // produces a unique entry
    Char *buf = new Char[4];
    buf[0] = 'f'; buf[1] = 'o'; buf[2] = 'x'; buf[3] = '\n';
    f::CorpusEntry<Char> *entry = new f::CorpusEntry<Char>(
        buf,
        4,
        new f::CoverageTracker()
    );

    Char *buf2 = new Char[4];
    buf2[0] = 'b'; buf2[1] = 'a'; buf2[2] = 'r'; buf2[4] = '\t';
    f::CorpusEntry<Char> *entry2 = new f::CorpusEntry<Char>(
        buf2,
        4,
        new f::CoverageTracker()
    );

    corp->Record(entry);
    corp->Record(entry2);
    
    REQUIRE( corp->Get(0) == entry );

    std::vector<Char *> children;
    for (size_t i=0; i<20; i++)
    {
        f::GenChildren<Char>(
            corp.get(),
            0,
            1,
            children
        );

        REQUIRE( children.size() == 1 );
        REQUIRE_FALSE( memcmp(children[0], buf, 4 * sizeof(Char)) == 0 );

        delete[] children[0];
        children.clear();
    }
}


TEST_CASE( "Mutator returns 0-len vector when asked" )
{
    std::shared_ptr<f::Corpus<uint8_t>> corp(new f::Corpus<uint8_t>);
    
    // make a new CorpusEntry so we can add it to corpus
    uint8_t *buf = new uint8_t[4];
    buf[0] = 'f'; buf[1] = 'o'; buf[2] = 'o'; buf[3] = '\n';
    f::CorpusEntry<uint8_t> *entry = new f::CorpusEntry<uint8_t>(
        buf,
        4,
        new f::CoverageTracker()
    );

    corp->Record(entry);
    
    std::vector<uint8_t *> children;
    f::GenChildren<uint8_t>(
        corp.get(),
        0,
        0,
        children
    );

    REQUIRE( children.size() == 0 );
}

TEST_CASE( "Mutator returns 0-len vector when asked (16-bit)" )
{
    std::shared_ptr<f::Corpus<uint16_t>> corp(new f::Corpus<uint16_t>);
    
    // make a new CorpusEntry so we can add it to corpus
    uint16_t *buf = new uint16_t[4];
    buf[0] = 'f'; buf[1] = 'o'; buf[2] = 'o'; buf[3] = '\n';
    f::CorpusEntry<uint16_t> *entry = new f::CorpusEntry<uint16_t>(
        buf,
        4,
        new f::CoverageTracker()
    );

    corp->Record(entry);
    
    std::vector<uint16_t *> children;
    f::GenChildren<uint16_t>(
        corp.get(),
        0,
        0,
        children
    );

    REQUIRE( children.size() == 0 );
}


TEST_CASE( "Mutator returns 1-len array of DIFFERENT buffer  (8-bit)" )
{
    test_mutate_gens_unique<uint8_t>();
}


TEST_CASE( "Mutator returns 1-len array of DIFFERENT buffer (16-bit)" )
{
    test_mutate_gens_unique<uint8_t>();
}


TEST_CASE( "Produces more children when prompted" )
{
    std::shared_ptr<f::Corpus<uint8_t>> corp(new f::Corpus<uint8_t>);
    
    // make a new CorpusEntry so we can add it to corpus
    uint8_t *buf = new uint8_t[4];
    buf[0] = 'f'; buf[1] = 'o'; buf[2] = 'o'; buf[3] = '\n';
    f::CorpusEntry<uint8_t> *entry = new f::CorpusEntry<uint8_t>(
        buf,
        4,
        new f::CoverageTracker()
    );

    corp->Record(entry);
    
    std::vector<uint8_t *> children;
    f::GenChildren<uint8_t>(
        corp.get(),
        0,
        20,
        children
    );

    REQUIRE( children.size() == 20 );

    for (size_t i=0; i<children.size(); i++)
    {
        delete[] children[i];
    }
}
