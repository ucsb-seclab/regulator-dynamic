#include <algorithm>
#include <cctype>
#include <string>
#include <iostream>

#include "argument-parser.hpp"
#include "cxxopts.hpp"

using namespace std;

namespace regulator
{

ParsedArguments ParsedArguments::Parse(int argc, char **argv)
{
    ParsedArguments ret;

    cxxopts::Options options(argv[0], "Regexp catastrophic backtracking fuzzer");
    options.add_options()
        ("f,flags", "Regexp flags", cxxopts::value<std::string>()->default_value(""))
        ("r,regexp", "The regexp to fuzz", cxxopts::value<std::string>())
        ("l,length", "The length of the string buffer to fuzz", cxxopts::value<uint32_t>()->default_value("0"))
        ("h,help", "Print help", cxxopts::value<bool>()->default_value("False"));

    cxxopts::ParseResult parsed = options.parse(argc, argv);

    if (parsed["help"].as<bool>())
    {
        std::cout << options.help() << std::endl;
        exit(0);
    }

    ret.flags = parsed["flags"].as<std::string>();
    ret.target_regex = parsed["regexp"].as<std::string>();
    ret.strlen = parsed["length"].as<uint32_t>();

    if (ret.target_regex.size() == 0)
    {
        std::cerr << "ERROR: regexp is required" << std::endl;
        std::cerr << std::endl;
        std::cerr << options.help() << std::endl;
        exit(1);
    }

    if (ret.strlen == 0)
    {
        std::cerr << "ERROR: length was nonzero or missing" << std::endl;
        std::cerr << std::endl;
        std::cerr << options.help() << std::endl;
        exit(1);
    }

    return ret;
}

}