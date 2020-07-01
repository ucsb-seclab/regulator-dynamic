// timer.hpp
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Simple timer utility to count executions/second

#pragma once

#include <cstdint>
#include <cstring>
#include <ctime>

namespace regulator
{
namespace timer
{

// number of windows in the buffer KEEP A MULTIPLE OF 2
const size_t num_windows = 8;

class Timer
{
public:
    Timer();
    ~Timer();

    /**
     * Returns the number of ticks per millisecond, according
     * to the sliding window in use.
     */
    uint64_t TicksPerS() const;

    /**
     * Increments the operation count by one
     */
    void TickOnce();

private:
    // a circular buffer
    uint64_t sliding_window[num_windows];
    size_t sliding_window_root = 0;

    std::time_t sliding_window_start;
};

}
}