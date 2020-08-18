#include <iostream>
#include <cstdint>

#include "v8.h"
#include "argument-parser.hpp"
#include "regexp-executor.hpp"
#include "fuzz-driver.hpp"
#include "flags.hpp"

using namespace std;

namespace f = regulator::flags;

static const char *MY_ZONE_NAME = "MY_ZONE";


int main(int argc, char* argv[])
{
    // Read and store our arguments.
    regulator::ParsedArguments args = regulator::ParsedArguments::Parse(argc, argv);

    if (f::FLAG_debug)
    {
        std::cout << "DEBUG enabled. Beginning fuzz run." << std::endl;
    }

    // Initialize
    v8::Isolate *isolate = regulator::executor::Initialize();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> ctx = v8::Context::New(isolate);
    ctx->Enter();

    if (f::FLAG_debug)
    {
        std::cout << "DEBUG Compiling for regexp: " << args.target_regex << std::endl;
    }

    // Compile the regexp
    regulator::executor::V8RegExp regexp;
    regulator::executor::Result compile_result = regulator::executor::Compile(
        args.target_regex.c_str(),
        args.flags.c_str(),
        &regexp,
        args.num_threads
    );

    if (compile_result != regulator::executor::kSuccess)
    {
        std::cerr << "Regexp compilation failed" << std::endl;
        exit(1);
    }

    if (f::FLAG_debug)
    {
        std::cout << "DEBUG Compiled, beginning fuzz" << std::endl;
    }


    uint64_t status = regulator::fuzz::Fuzz(
        isolate,
        &regexp,
        args.strlens,
        args.fuzz_one_byte,
        args.fuzz_two_byte,
        args.num_threads
    );

    return ~status;
}
