#include "fuzz/coverage-tracker.hpp"

#include "catch.hpp"

using namespace regulator::fuzz;

TEST_CASE( "Should construct and destruct" )
{
    CoverageTracker *cc = new CoverageTracker();
    delete cc;
}


TEST_CASE( "Should construct with sane defaults" )
{
    CoverageTracker cc1;
    CoverageTracker cc2;

    REQUIRE_FALSE( cc1.EdgeIsCovered(3) );
    REQUIRE_FALSE( cc1.EdgeIsGreater(&cc2, 6) );
    REQUIRE_FALSE( cc1.HasNewPath(&cc2) );
    REQUIRE( cc2.EdgeIsEqual(&cc1, 5) );
    REQUIRE( cc1.FinalCursorPosition() == SIZE_MAX );
}


TEST_CASE( "Should be able to record a branch" )
{
    CoverageTracker cc;
    cc.Cover(1, 4);
}
