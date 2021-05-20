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
 * The type of output that should be produced
 */
enum target_output {
    /**
     * Unset
     */
    kUnassigned,

    /**
     * Should generate bytecode regex output
     */
    kByteCode,

    /**
     * Should generate native code
     */
    kNativeCode,
};


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
     * The target output type
     */
    target_output target;
    /**
     * Where to output the file
     */
    std::string output_file_name;

    /**
     * Indicates character width
     */
    bool one_wide;

    /**
     * Parses command-line arguments
     */
    static ParsedArguments Parse(int argc, char **argv);
};


} // end namespace regulator
