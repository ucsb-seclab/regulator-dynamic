#include "fuzz/corpus.hpp"
#include "fuzz/coverage-tracker.hpp"

#include "catch.hpp"

#include <cstring>
#include <iostream>

using namespace regulator::fuzz;

TEST_CASE( "Initialize and destroy corpus entry" )
{
    uint8_t buf[] = {'a', 'b', 'c', 'd'};
    size_t buflen = sizeof(buf);
    CoverageTracker *ctrak = new CoverageTracker;
    ctrak->Cover(0xDEADBEEF, 0xFACECAFE);

    uint8_t *tmpbuf = new uint8_t[sizeof(buf)];
    memcpy(tmpbuf, buf, sizeof(buf));
    CorpusEntry *entry = new CorpusEntry(tmpbuf, buflen, ctrak);

    REQUIRE( entry->buf != nullptr);
    REQUIRE( entry->buflen == buflen );
    REQUIRE( memcmp(entry->buf, buf, buflen) == 0 );
    REQUIRE( entry->coverage_tracker != nullptr );

    delete entry;
}


TEST_CASE( "Construct Corpus" )
{
    Corpus *corp = new Corpus();

    REQUIRE( corp->Size() == 0 );
    REQUIRE( corp->GetOne() == nullptr );

    delete corp;
}


TEST_CASE( "Add records to corpus" )
{
    Corpus *corp = new Corpus();

    uint8_t buf[] = {'a', 'b', 'c', 'd'};
    size_t buflen = sizeof(buf);

    CoverageTracker *ctrak = new CoverageTracker;
    ctrak->Cover(0xDEADBEEF, 0xFACECAFE);

    uint8_t *tmpbuf = new uint8_t[sizeof(buf)];
    memcpy(tmpbuf, buf, sizeof(buf));
    CorpusEntry *entry = new CorpusEntry(tmpbuf, buflen, ctrak);

    corp->Record(entry);

    REQUIRE( corp->Size() == 1 );
    REQUIRE( corp->GetOne() != nullptr );
    REQUIRE( corp->GetOne() == entry );

    delete corp;
}
