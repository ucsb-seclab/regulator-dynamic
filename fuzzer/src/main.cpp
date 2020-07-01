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
        std::cout << "Compiling for regexp: " << args.target_regex << std::endl;
    }

    // Compile the regexp
    regulator::executor::V8RegExp regexp;
    regulator::executor::Result compile_result = regulator::executor::Compile(
        args.target_regex.c_str(),
        args.flags.c_str(), &regexp
    );

    if (compile_result != regulator::executor::kSuccess)
    {
        std::cerr << "Regexp compilation failed" << std::endl;
        exit(1);
    }

    if (f::FLAG_debug)
    {
        std::cout << "Compiled, beginning fuzz" << std::endl;
    }

    uint8_t *out = new uint8_t[args.strlen];
    uint64_t opcount = regulator::fuzz::Fuzz(isolate, &regexp, out, args.strlen);

    std::cout << "found opcount: " << opcount << std::endl;

    delete[] out;
}
