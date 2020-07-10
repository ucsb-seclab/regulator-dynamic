#include <iostream>
#include <vector>

#include "fuzz/mutator.hpp"

#include "catch.hpp"

namespace f = regulator::fuzz;

template<typename Char>
inline void test_mutate_gens_unique()
{
    Char *parent = new Char[4];
    parent[0] = 'p'; parent[1] = 'r'; parent[2] = 'n'; parent[3] = 't';

    std::vector<Char *> children;
    std::vector<Char> extra_interesting;
    std::vector<Char *> coparent_buffer;

    for (size_t i=0; i<20; i++)
    {
        // make a unique buffer for the coparent
        Char *coparent = new Char[4];
        coparent[0] = 'f'; coparent[1] = 'o'; coparent[2] = 'x'; coparent[3] = '\n';
        coparent_buffer.push_back(coparent);

        f::GenChildren(
            parent,
            4 /* number of chars in parent */,
            1 /* n children */,
            coparent_buffer,
            extra_interesting,
            children
        );

        REQUIRE( children.size() == 1 );
        REQUIRE_FALSE( memcmp(children[0], parent, 4 * sizeof(Char)) == 0 );

        delete[] children[0];
        children.clear();
        
        if (coparent_buffer.size() > 0)
        {
            delete[] coparent_buffer[0];
            coparent_buffer.clear();
        }
    }

    delete[] parent;
}


TEST_CASE( "Mutator returns 0-len vector when asked" )
{
    // make a new parent buffer
    uint8_t *buf = new uint8_t[4];
    buf[0] = 'f'; buf[1] = 'o'; buf[2] = 'o'; buf[3] = '\n';

    std::vector<uint8_t *> children;
    std::vector<uint8_t> extra_interesting;
    std::vector<uint8_t *> coparent_buffer;
    f::GenChildren(
        buf,
        4,
        0,
        coparent_buffer,
        extra_interesting,
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
    std::vector<uint16_t> extra_interesting;
    std::vector<uint16_t *> coparent_buffer;
    f::GenChildren(
        buf,
        4,
        0,
        coparent_buffer,
        extra_interesting,
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
    test_mutate_gens_unique<uint8_t>();
}


TEST_CASE( "Produces more children when prompted" )
{
    // make a parent buffer
    uint8_t *buf = new uint8_t[4];
    buf[0] = 'f'; buf[1] = 'o'; buf[2] = 'o'; buf[3] = '\n';

    // make a bunch of potential coparents
    std::vector<uint8_t *> coparents;
    for (size_t i=0; i<20; i++)
    {
        uint8_t *coparent_buf = new uint8_t[4];
        coparent_buf[0] = (i * 4);
        coparent_buf[1] = (i * 4) + 1;
        coparent_buf[2] = (i * 4) + 2;
        coparent_buf[3] = (i * 4) + 3;
        coparents.push_back(coparent_buf);
    }

    std::vector<uint8_t *> children;
    std::vector<uint8_t> extra_interesting;
    f::GenChildren(
        buf,
        4,
        20,
        coparents,
        extra_interesting,
        children
    );

    REQUIRE( children.size() == 20 );

    for (size_t i=0; i<children.size(); i++)
    {
        delete[] children[i];
    }
    for (size_t i=0; i<coparents.size(); i++)
    {
        delete[] coparents[i];
    }
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

TEST_CASE( "crossover will pop from the vector" )
{
    uint8_t parent[] = {'f', 'o', 'o', 'b', 'a', 'r'};
    uint8_t *coparent = new uint8_t[sizeof(parent)];
    memset(coparent, 'x', sizeof(parent));

    std::vector<uint8_t *> coparents;
    coparents.push_back(coparent);
    f::crossover(parent, sizeof(parent), coparents);

    REQUIRE( coparents.size() == 0 );
}
