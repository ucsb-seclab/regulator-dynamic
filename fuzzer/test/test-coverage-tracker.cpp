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
