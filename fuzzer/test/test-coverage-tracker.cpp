#include "fuzz/coverage-tracker.hpp"

#include "catch.hpp"

using namespace regulator::fuzz;

TEST_CASE( "Should construct and destruct" )
{
    CoverageTracker *cc = new CoverageTracker();
    delete cc;
}


TEST_CASE( "Should be able to record a branch" )
{
    CoverageTracker cc;
    cc.Cover(1, 4);
}


TEST_CASE( "Should show popcount of 0 for 0 coverage record" )
{
    CoverageTracker cc;

    REQUIRE( cc.Popcount() == 0 );
}


TEST_CASE( "Should show popcount of 1 for 1 coverage record" )
{
    CoverageTracker cc;
    cc.Cover(0, 8);

    REQUIRE( cc.Popcount() == 1 );
}

TEST_CASE( "Should show popcount of 2 for 2 coverage record" )
{
    CoverageTracker cc;
    cc.Cover(0, 8);
    cc.Cover(16, 32);

    REQUIRE( cc.Popcount() == 2 );
}
