#include <algorithm>
#include <cctype>
#include <string>
#include <iostream>
#include <random>

#include "argument-parser.hpp"
#include "cxxopts.hpp"
#include "flags.hpp"

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
        ("t,timeout", "Timeout, in number of seconds", cxxopts::value<uint32_t>()->default_value("0"))
        ("s,seed", "Seed for random number generator", cxxopts::value<uint32_t>()->default_value("0"))
        ("w,widths", "Which byte-widths to fuzz: use either 1, 2, or \"1,2\"", cxxopts::value<std::string>()->default_value(""))
        ("debug", "Enable debug mode", cxxopts::value<bool>()->default_value("False"))
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
    ret.fuzz_one_byte = true;
    ret.fuzz_two_byte = true;

    regulator::flags::FLAG_timeout = parsed["timeout"].as<uint32_t>();
    regulator::flags::FLAG_debug = parsed["debug"].as<bool>();

    if (regulator::flags::FLAG_timeout == 0)
    {
        std::cerr << "ERROR: timeout is required" << std::endl;
        std::cerr << std::endl;
        std::cerr << options.help() << std::endl;
        exit(1);
    }

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

    std::string byte_widths = parsed["widths"].as<std::string>();
    if (byte_widths == "1")
    {
        ret.fuzz_one_byte = true;
        ret.fuzz_two_byte = false;
    }
    else if (byte_widths == "2")
    {
        ret.fuzz_one_byte = false;
        ret.fuzz_two_byte = true;
    }
    else if (byte_widths == "" || byte_widths == "1,2" || byte_widths == "2,1")
    {
        ret.fuzz_one_byte = true;
        ret.fuzz_two_byte = true;
    }
    else
    {
        std::cout << "ERROR: unknown widths argument: " << byte_widths << std::endl;
        exit(1);
    }

    uint32_t seed = parsed["seed"].as<uint32_t>();
    if (seed > 0)
    {
        if (regulator::flags::FLAG_debug)
        {
            std::cout << "DEBUG Seeding random number generator with " << seed << std::endl;
        }
        srand(seed);
    }

    return ret;
}

}