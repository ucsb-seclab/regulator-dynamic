#include <iostream>
#include <vector>
#include <memory>

#include "fuzz/corpus.hpp"

#include "catch.hpp"

namespace f = regulator::fuzz;

template<typename Char>
inline void test_mutate_gens_unique()
{
    Char *parent = new Char[6];
    parent[0] = sizeof(Char) == 1 ? 'p' : 0x0222;
    parent[1] = 0xa;
    parent[2] = 'r';
    parent[3] = 'e';
    parent[4] = 'n';
    parent[5] = 't';

    std::vector<Char *> children;
    std::vector<Char> extra_interesting;
    std::vector<Char *> coparent_buffer;

    regulator::fuzz::Corpus<Char> corpus;
    corpus.Record(new regulator::fuzz::CorpusEntry<Char>(
        parent,
        6,
        new regulator::fuzz::CoverageTracker()
    ));
    corpus.FlushGeneration();

    for (size_t i=0; i<20; i++)
    {
        // make a unique buffer for the coparent
        Char *coparent = new Char[6];
        coparent[0] = 'd';
        coparent[1] = 'o';
        coparent[2] = 'l';
        coparent[3] = 'm';
        coparent[4] = 'a';
        coparent[5] = 's';

        corpus.GenerateChildren(
            coparent,
            6,
            1,
            children
        );

        REQUIRE( children.size() == 1 );
        REQUIRE_FALSE( memcmp(children[0], coparent, 6 * sizeof(Char)) == 0 );

        delete[] children[0];
        children.clear();
    }
}


TEST_CASE( "Mutator returns 0-len vector when asked" )
{
    // make a new parent buffer
    uint8_t *buf = new uint8_t[4];
    buf[0] = 'f'; buf[1] = 'o'; buf[2] = 'o'; buf[3] = '\n';

    std::vector<uint8_t *> children;
    regulator::fuzz::Corpus<uint8_t> corpus;
    corpus.GenerateChildren(
        buf,
        4,
        0,
        children
    );

    REQUIRE( children.size() == 0 );

    delete[] buf;
}

TEST_CASE( "Mutator returns 0-len vector when asked (16-bit)" )
{
    // make a new parent buffer
    uint16_t *buf = new uint16_t[4];
    buf[0] = 'f'; buf[1] = 'o'; buf[2] = 'o'; buf[3] = '\n';

    std::vector<uint16_t *> children;
    regulator::fuzz::Corpus<uint16_t> corpus;
    corpus.GenerateChildren(
        buf,
        4,
        0,
        children
    );

    REQUIRE( children.size() == 0 );

    delete[] buf;
}


TEST_CASE( "Mutator returns 1-len array of DIFFERENT buffer  (8-bit)" )
{
    test_mutate_gens_unique<uint8_t>();
}


TEST_CASE( "Mutator returns 1-len array of DIFFERENT buffer (16-bit)" )
{
    test_mutate_gens_unique<uint16_t>();
}


TEST_CASE( "Produces more children when prompted" )
{
    uint8_t *parent = new uint8_t[6];
    parent[0] = 'p';
    parent[1] = 0xa;
    parent[2] = 'r';
    parent[3] = 'e';
    parent[4] = 'n';
    parent[5] = 't';

    std::vector<uint8_t *> children;
    std::vector<uint8_t> extra_interesting;
    std::vector<uint8_t *> coparent_buffer;

    regulator::fuzz::Corpus<uint8_t> corp;
    corp.Record(new regulator::fuzz::CorpusEntry<uint8_t>(
        parent,
        6,
        new regulator::fuzz::CoverageTracker()
    ));
    corp.FlushGeneration();

    // make a unique buffer for the coparent
    uint8_t *coparent = new uint8_t[6];
    coparent[0] = 'd';
    coparent[1] = 'o';
    coparent[2] = 'l';
    coparent[3] = 'm';
    coparent[4] = 'a';
    coparent[5] = 's';

    corp.GenerateChildren(
        coparent,
        6,
        20,
        children
    );

    REQUIRE( children.size() == 20 );

    for (size_t i=0; i<children.size(); i++)
    {
        delete[] children[i];
    }

    children.clear();
}

TEST_CASE( "bit-flip will change exactly one bit (1-byte)" )
{
    uint8_t subject[] = {'a', 'b', 'c', 'd'};

    uint8_t cpy[sizeof(subject)];

    for (size_t i=0; i<20; i++)
    {
        memcpy(cpy, subject, sizeof(subject));

        f::bit_flip(cpy, sizeof(subject));

        size_t popcount = 0;
        for (size_t i=0; i<sizeof(subject); i++)
        {
            popcount += __builtin_popcount(subject[i] ^ cpy[i]);
        }

        REQUIRE( popcount == 1 );
    }
}

TEST_CASE( "bit-flip will change exactly one bit (2-byte)" )
{
    uint16_t subject[] = {'a', 'b', 'c', 'd'};

    uint16_t cpy[sizeof(subject) / 2];

    for (size_t i=0; i<20; i++)
    {
        memcpy(cpy, subject, sizeof(subject));

        f::bit_flip(cpy, sizeof(subject) / 2);

        size_t popcount = 0;
        for (size_t i=0; i<sizeof(subject) / 2; i++)
        {
            popcount += __builtin_popcount(subject[i] ^ cpy[i]);
        }

        REQUIRE( popcount == 1 );
    }
}

TEST_CASE( "crossover will use another buffer" )
{
    uint8_t parent[] = {'f', 'o', 'o', 'b', 'a', 'r'};
    uint8_t *coparent = new uint8_t[sizeof(parent)];
    memset(coparent, 'x', sizeof(parent));

    f::crossover(parent, sizeof(parent), coparent);

    delete[] coparent;
}

TEST_CASE( "mutate will eventually place an interesting utf-16 char ")
{
    uint16_t parent[5];

    uint16_t *coparent = new uint16_t[5];
    coparent[0] = 'a';
    coparent[1] = 'b';
    coparent[2] = 'c';
    coparent[3] = 'd';
    coparent[4] = 'e';

    f::Corpus<uint16_t> corpus;
    corpus.Record(new f::CorpusEntry<uint16_t>(
        coparent,
        5,
        new f::CoverageTracker()
    ));

    corpus.FlushGeneration();
    std::vector<uint16_t *> children;
    std::vector<uint16_t> *interesting = new std::vector<uint16_t>;
    interesting->push_back(0xCAFE);
    corpus.SetInteresting(interesting);

    bool found_special = false;

    for (size_t i=0; i < 200 && !found_special; i++)
    {
        children.clear();
        parent[0] = 'w';
        parent[1] = 'x';
        parent[2] = 'y';
        parent[3] = 'z';
        parent[4] = '!';

        corpus.GenerateChildren(
            parent,
            5,
            10,
            children
        );

        REQUIRE( children.size() == 10 );

        for (size_t j=0; j<children.size(); j++)
        {
            for (size_t k=0; k<5; k++)
            {
                found_special = found_special || children[j][k] == 0xCAFE;
            }
            delete[] children[j];
        }
    }

    REQUIRE( found_special );
}
