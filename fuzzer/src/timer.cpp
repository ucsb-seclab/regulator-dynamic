#include "timer.hpp"

#include <algorithm>
#include <ctime>
#include <iostream>

namespace regulator
{
namespace timer
{

Timer::Timer()
{
    for (size_t i = 0; i < num_windows; i++)
    {
        this->sliding_window[i] = 0;
    }

    this->sliding_window_start = std::time(0);
}

Timer::~Timer() {}

void Timer::TickOnce()
{
    std::time_t t = std::time(0);
    uint64_t slot = t - this->sliding_window_start;
    
    // if we've exceeded the sliding window second count then
    // rotate the window
    if (slot >= num_windows)
    {
        // Find the number of windows we can reclaim
        uint64_t to_slide = std::min(num_windows, slot - num_windows + 1);
        
        // Reclaim `to_slide` windows
        for (size_t i = 0; i < to_slide; i++)
        {
            this->sliding_window[(this->sliding_window_root + i) & (num_windows - 1)] = 0;
        }

        // Move the root
        this->sliding_window_root = (this->sliding_window_root + to_slide) & (num_windows - 1);
        this->sliding_window_start += to_slide;

    }

    slot &= num_windows - 1;

    // Tick-Increment
    this->sliding_window[slot]++;
}

uint64_t Timer::TicksPerS() const
{
    uint64_t tot_ticks = 0;
    
    for (size_t i=0; i<num_windows; i++)
    {
        tot_ticks += this->sliding_window[i];
    }

    std::time_t t = std::time(0);
    uint64_t secs_elapsed = std::max(1l, (t - this->sliding_window_start));

    return tot_ticks / secs_elapsed;
}

}
}