// argument_parser.hpp
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Parses arguments for the regulator regex code extractor
//

#pragma once

#include <string>
#include <stdint.h>

namespace regulator
{

/**
 * Holds details about parsed command-line arguments
 */
class ParsedArguments {
public:
    /**
     * The regex to run
     */
    std::string target_regex;
    /**
     * The regex flags
     */
    std::string flags;

    /**
     * The string length to fuzz
     */
    uint32_t strlen;

    /**
     * Whether to fuzz one-byte strings
     */
    bool fuzz_one_byte;

    /**
     * Whether to fuzz two-byte strings
     */
    bool fuzz_two_byte;

    /**
     * Parses command-line arguments
     */
    static ParsedArguments Parse(int argc, char **argv);
};


} // end namespace regulator
