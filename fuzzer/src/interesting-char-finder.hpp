// interesting-char-finder.hpp
//
// Author: Robert McLaughlin <robert349@uscb.edu>
//
// Finds interesting characters hard-coded in regexp bytecode
//

#pragma once

#include <vector>

#include "regexp-executor.hpp"

namespace regulator
{
namespace fuzz
{
/**
 * Finds and records all interesting characters known for this regex
 * 
 * Returns True on success, otherwise False
 */
template<typename Char>
bool ExtractInteresting(
    regulator::executor::V8RegExp &regexp,
    std::vector<Char> &out
);

}
}
