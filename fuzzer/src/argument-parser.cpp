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

inline static bool base64_decode(const std::string &in, uint8_t *&out, size_t &outlen) {
    // adapted from https://stackoverflow.com/a/13935718
    std::vector<uint8_t> vout;

    std::vector<int> T(256,-1);
    for (int i=0; i<64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i; 

    int val=0, valb=-8;
    for (uint8_t c : in) {
        if (T[c] == -1) break;
        val = (val<<6) + T[c];
        valb += 6;
        if (valb>=0) {
            vout.push_back(char((val>>valb)&0xFF));
            valb-=8;
        }
    }

    out = new uint8_t[vout.size() + 1];
    for (size_t i=0; i < vout.size(); i++)
    {
        out[i] = vout[i];
    }

    out[vout.size()] = 0;

    outlen = vout.size();

    return true;
}


ParsedArguments ParsedArguments::Parse(int argc, char **argv)
{
    ParsedArguments ret;

    cxxopts::Options options(argv[0], "Regexp catastrophic backtracking fuzzer");
    options.add_options()
        ("f,flags", "Regexp flags", cxxopts::value<std::string>()->default_value(""))
        ("r,regexp", "The regexp to fuzz, as an ascii string", cxxopts::value<std::string>())
        ("b,bregexp", "The regexp to fuzz, as a base64 utf8 string", cxxopts::value<std::string>())
        ("l,lengths", "The length(s) of the string buffer to fuzz, comma-separated", cxxopts::value<std::string>()->default_value("0"))
        ("e,etimeout", "Cease fuzzing of a specific fuzz-length if no progress was made within this many seconds", cxxopts::value<int32_t>())
        ("t,timeout", "Timeout, in number of seconds", cxxopts::value<int32_t>())
        ("s,seed", "Seed for random number generator", cxxopts::value<uint32_t>()->default_value("0"))
        ("w,widths", "Which byte-widths to fuzz: use either 1, 2, or \"1,2\"", cxxopts::value<std::string>()->default_value(""))
        ("m,threads", "How many threads to use", cxxopts::value<uint16_t>()->default_value("1"))
        ("debug", "Enable debug mode", cxxopts::value<bool>()->default_value("False"))
        ("h,help", "Print help", cxxopts::value<bool>()->default_value("False"));

    cxxopts::ParseResult parsed = options.parse(argc, argv);

    if (parsed["help"].as<bool>())
    {
        std::cout << options.help() << std::endl;
        exit(0);
    }

    if (parsed["regexp"].count() > 0)
    {
        std::string regexp = parsed["regexp"].as<std::string>();
        uint8_t *buf = new uint8_t[regexp.size() + 1];
        memcpy(buf, regexp.c_str(), regexp.size());
        buf[regexp.size()] = '\0';
        ret.target_regex = buf;
        ret.target_regex_len = regexp.size();
    }
    else if (parsed["bregexp"].count() > 0)
    {
        std::string regexp = parsed["bregexp"].as<std::string>();
        if (!base64_decode(regexp, ret.target_regex, ret.target_regex_len))
        {
            std::cerr << "Could not decode base64" << std::endl;
            std::cerr << std::endl;
            std::cerr << options.help() << std::endl;
            exit(1);
        }
    }
    else
    {
        std::cerr << "Found neither --regexp nor --bregexp" << std::endl;
        std::cerr << std::endl;
        std::cerr << options.help() << std::endl;
        exit(1);
    }

    ret.flags = parsed["flags"].as<std::string>();
    ret.num_threads = parsed["threads"].as<uint16_t>();
    ret.fuzz_one_byte = true;
    ret.fuzz_two_byte = true;

    ret.timeout_secs = -1;
    if (parsed["timeout"].count() > 0)
    {
        ret.timeout_secs = parsed["timeout"].as<int32_t>();

        if (ret.timeout_secs <= 0)
        {
            std::cerr << "ERROR: timeout must be positive" << std::endl;
            std::cerr << std::endl;
            std::cerr << options.help() << std::endl;
            exit(1);
        }
    }

    ret.individual_timeout_secs = -1;
    if (parsed["etimeout"].count() > 0)
    {
        ret.individual_timeout_secs = parsed["etimeout"].as<int32_t>();

        if (ret.individual_timeout_secs <= 0)
        {
            std::cerr << "ERROR: etimeout must be positive" << std::endl;
            std::cerr << std::endl;
            std::cerr << options.help() << std::endl;
            exit(1);
        }
    }

    regulator::flags::FLAG_debug = parsed["debug"].as<bool>();

    std::string lengths = parsed["lengths"].as<std::string>();
    size_t next_search_idx = 0;
    while (next_search_idx != std::string::npos)
    {
        size_t next_comma_idx = lengths.find(',', next_search_idx);
        size_t this_len;
        if (next_comma_idx == std::string::npos)
        {
            std::string s = lengths.substr(next_search_idx);
            this_len = stoul(s);
        }
        else
        {
            std::string s = lengths.substr(next_search_idx, next_comma_idx - next_search_idx);
            this_len = stoul(s);
        }

        ret.strlens.push_back(this_len);

        // advance past the ','
        next_search_idx = next_comma_idx == std::string::npos ? std::string::npos : next_comma_idx + 1;
    }

    if (ret.target_regex_len == 0)
    {
        std::cerr << "ERROR: regexp is required" << std::endl;
        std::cerr << std::endl;
        std::cerr << options.help() << std::endl;
        exit(1);
    }

    if (ret.strlens.size() == 0)
    {
        std::cerr << "ERROR: lengths was missing" << std::endl;
        std::cerr << std::endl;
        std::cerr << options.help() << std::endl;
        exit(1);
    }

    // ensure that the lengths are reasonable
    for (size_t i=0; i < ret.strlens.size(); i++)
    {
        if (ret.strlens[i] == 0 || ret.strlens[i] > UINT16_MAX)
        {
            std::cerr << "ERROR: the length is not supported: " << ret.strlens[i] << std::endl;
            std::cerr << std::endl;
            std::cerr << options.help() << std::endl;
            exit(1);
        }
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
        std::cerr << "ERROR: unknown widths argument: " << byte_widths << std::endl;
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