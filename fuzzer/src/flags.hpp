// flags.hpp
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Makes global flags available

#pragma once

#include <cstdint>

namespace regulator
{
namespace flags
{
/**
 * Sets the maximum time to fuzz the regexp program
 */
extern uint64_t FLAG_timeout;

/**
 * Enables debug output
 */
extern bool FLAG_debug;

}
}