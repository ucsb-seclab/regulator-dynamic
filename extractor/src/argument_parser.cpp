#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <iostream>
#include <cstdio>
#include <unistd.h>
#include "argument_parser.hpp"

using namespace std;

namespace regulator
{

void read_regexp(char * &buffer, size_t &nread){
    buffer = (char *)malloc(4096);
    nread = 0;
    while (!feof(stdin)) {
        std::cout << "reading" << std::endl;
        size_t r = read(STDIN_FILENO, buffer + nread, (4096 - 1) - nread);
        if (r == 0)
        {
            break;
        }
        else
        {
            nread += r;
        }
        if (nread == 4096 - 1)
        {
            break;
        }
    }
    buffer[nread + 1] = 0;
}

static const std::string USAGE_TXT = \
"USAGE: extractor [options] REGEXP OUTPUT_FILE\n"
"\n"
"Compiles and extracts regexp matching code from V8\n"
"\n"
"options:\n"
"    --bytecode     Generate bytecode output\n"
"    --native       Generate native (x86_64) output\n"
"    --flags FLAGS  Regex flags (i, m, u, etc...)\n"
"    --width 1|2    The char-width to target";


ParsedArguments ParsedArguments::Parse(int argc, char **argv)
{
    ParsedArguments ret;

    bool found_width = false;
    bool regex_stdin = false;

    int arg_idx = 1;
    for (; arg_idx < argc; arg_idx++)
    {
        string arg(argv[arg_idx]);
        // lowercase the string
        std::transform(arg.begin(), arg.end(), arg.begin(),
            [](unsigned char c){ return std::tolower(c); });

        if (arg.compare("-h") == 0 || arg.compare("--h") == 0)
        {
            cout << USAGE_TXT << endl;
            exit(0);
        }

        if (arg.find("--") != 0)
        {
            // must be the regex
            break;
        }

        if (arg.compare("--") == 0)
        {
            // regex from stdin
            regex_stdin = true;
            break;
        }

        if (arg.compare("--bytecode") == 0)
        {
            ret.target = kByteCode;
            continue;
        }

        if (arg.compare("--native") == 0)
        {
            ret.target = kNativeCode;
            continue;
        }

        if (arg.compare("--flags") == 0)
        {
            // advance to get next arg
            arg_idx++;
            if (arg_idx >= argc)
            {
                cerr << "--flags must be followed with flags" << endl;
                exit(1);
            }
            ret.flags.clear();
            ret.flags.append(argv[arg_idx]);
            cout << "Found flags: " << ret.flags << endl;
            continue;
        }

        if (arg.compare("--width") == 0)
        {
            found_width = true;
            arg_idx++;
            if (arg_idx >= argc)
            {
                cerr << "--width must be followed by 1 or 2" << endl;
                exit(1);
            }
            if (std::string(argv[arg_idx]).compare("1") == 0)
            {
                ret.one_wide = true;
            }
            else if (std::string(argv[arg_idx]).compare("2") == 0)
            {
                ret.one_wide = false;
            }
            else
            {
                cerr << "Unknown character width" << endl;
                exit(1);
            }
            continue;
        }

        cerr << "Unknown argument: " << arg << endl;
        exit(1);
    }

    if (!found_width)
    {
        cerr << "Must specify a --width" << endl;
        exit(1);
    }

    // should have set these by now
    if (ret.target == kUnassigned)
    {
        cerr << "Please pass either --native or --bytecode" << endl;
        exit(1);
    }

    // next position should be the target regex
    if (argc <= arg_idx)
    {
        cerr << "Please pass regex pattern in arguments" << endl;
        exit(1);
    }

    if (regex_stdin)
    {
        read_regexp(ret.target_regex, ret.target_regex_size);
    }
    else
    {
        ret.target_regex = argv[arg_idx];
        ret.target_regex_size = strlen(argv[arg_idx]);
    }
    arg_idx++;

    if (argc <= arg_idx)
    {
        cerr << "Please pass output file in arguments" << endl;
        exit(1);
    }

    ret.output_file_name.clear();
    ret.output_file_name.append(argv[arg_idx]);

    if (argc != arg_idx + 1)
    {
        cerr << "Unknown extra arguments" << endl;
        exit(1);
    }

    // search flags
    return ret;
}

}