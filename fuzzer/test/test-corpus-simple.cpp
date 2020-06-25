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
    CoverageTracker ctrak;
    ctrak.Cover(0xDEADBEEF, 0xFACECAFE);
    
    CorpusEntry *entry = new CorpusEntry(buf, buflen, 1337, &ctrak);
    
    REQUIRE( entry->buf != nullptr);
    REQUIRE( entry->buflen == buflen );
    REQUIRE( memcmp(entry->buf, buf, buflen) == 0 );
    REQUIRE( entry->coverage_tracker != nullptr );
    REQUIRE( entry->coverage_tracker->Popcount() == 1 );

    delete entry;
}


TEST_CASE( "Deep copy corpus entry" )
{
    uint8_t buf[] = {'a', 'b', 'c', 'd'};
    size_t buflen = sizeof(buf);
    CoverageTracker ctrak;
    ctrak.Cover(0xDEADBEEF, 0xFACECAFE);
    
    CorpusEntry *entry = new CorpusEntry(buf, buflen, 1337, &ctrak);
    
    REQUIRE( entry->buf != buf);
    REQUIRE( entry->coverage_tracker != &ctrak );
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
    CoverageTracker ctrak;
    ctrak.Cover(0xDEADBEEF, 0xFACECAFE);
    
    CorpusEntry *entry = new CorpusEntry(buf, buflen, 1337, &ctrak);

    corp->Record(entry);

    REQUIRE( corp->Size() == 1 );
    REQUIRE( corp->GetOne() != nullptr );
    REQUIRE( corp->GetOne() == entry );

    delete corp;
}


TEST_CASE( "Full corpus evicts not-as-good entries" )
{
    Corpus *corp = new Corpus();

    uint8_t buf1[] = {'a', 'b', 'c', 'd'};
    size_t buflen1 = sizeof(buf1);

    CoverageTracker ctrak1;
    ctrak1.Cover(0xDEADBEEF, 0xFACECAFE);

    for (size_t i = 0; i < Corpus::MaxEntries; i++)
    {
        CorpusEntry *entry1 = new CorpusEntry(buf1, buflen1, 1337, &ctrak1);
        corp->Record(entry1);
    }

    // corpus is now full, add a more-good entry
    uint8_t buf2[] = {'a', 'b', 'c', 'd'};
    size_t buflen2 = sizeof(buf2);

    CoverageTracker ctrak2;
    ctrak2.Cover(0xDEADBEEF, 0xFACECAFE);
    ctrak2.Cover(0xFEEDFACE, 0x1337FADE);
    ctrak2.Cover(0x12345678, 0x32132132);
    CorpusEntry *entry2 = new CorpusEntry(buf2, buflen2, 1337 * 5, &ctrak2);


    REQUIRE( corp->Size() == Corpus::MaxEntries );

    REQUIRE( corp->GetOne()->Goodness() < entry2->Goodness() );

    corp->Record(entry2);

    REQUIRE( corp->Size() == Corpus::MaxEntries );

    // ensure that entry2 can be found in the corpus
    bool found = false;
    for (size_t i = 0; !found && i < corp->Size(); i++)
    {
        if (corp->Get(i) == entry2)
        {
            found = true;
        }
    }

    REQUIRE( found );

    delete corp;
}
