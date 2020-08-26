// argument_parser.hpp
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Parses arguments for the regulator regex code extractor
//

#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace regulator
{

/**
 * Holds details about parsed command-line arguments
 */
class ParsedArguments {
public:
    /**
     * The regex to run, as utf8
     */
    uint8_t *target_regex;

    /**
     * The length of the regex to run (in number of bytes)
     */
    size_t target_regex_len;

    /**
     * The regex flags
     */
    std::string flags;

    /**
     * The string length to fuzz
     */
    std::vector<size_t> strlens;

    /**
     * Whether to fuzz one-byte strings
     */
    bool fuzz_one_byte;

    /**
     * Whether to fuzz two-byte strings
     */
    bool fuzz_two_byte;

    /**
     * The number of threads to use
     */
    uint16_t num_threads;

    /**
     * Timeout, in number of seconds, for the entire fuzz campaign.
     * 
     * -1 indicates no timeout
     */
    int32_t timeout_secs;

    /**
     * Timeout, in number of seconds, for an individual string length.
     * 
     * If no progress has been made within this many seconds, give up on
     * the fuzz campaign.
     *
     * -1 indicates no timeout
     */
    int32_t individual_timeout_secs;

    /**
     * Parses command-line arguments
     */
    static ParsedArguments Parse(int argc, char **argv);
};


} // end namespace regulator
