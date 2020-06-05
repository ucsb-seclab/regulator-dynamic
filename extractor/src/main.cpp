#include <iostream>
#include <fstream>

#include "include/v8.h"
#include "src/execution/isolate.h"
#include "src/objects/objects.h"
#include "src/objects/js-regexp.h"
#include "src/objects/js-regexp-inl.h"
#include "src/regexp/regexp-bytecode-generator.h"
#include "src/regexp/regexp.h"
#include "src/objects/fixed-array.h"
#include "src/objects/fixed-array-inl.h"
#include "include/libplatform/libplatform.h"

#include "argument_parser.hpp"

using namespace std;

static const char *MY_ZONE_NAME = "MY_ZONE";


int main(int argc, char* argv[])
{
    // Read and store our arguments.
    regulator::ParsedArguments args = regulator::ParsedArguments::Parse(argc, argv);


    //
    // Initialization, largely taken from v8/test/cctest.cc
    //
    v8::V8::InitializeICUDefaultLocation(argv[0]);
    std::unique_ptr<v8::Platform> platform(v8::platform::NewDefaultPlatform());
    v8::V8::InitializePlatform(platform.get());

    // note: we need to set the flags, so let's just make a fake argc and argv
    {
        char *fake_argv[] = {argv[0], NULL};
        int fake_argc = 1;
        v8::internal::FlagList::SetFlagsFromCommandLine(&fake_argc, fake_argv, false);
    }

    v8::V8::Initialize();
    v8::V8::InitializeExternalStartupData(argv[0]);


    v8::ArrayBuffer::Allocator *allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();

    v8::Isolate::CreateParams isolateCreateParams;
    isolateCreateParams.array_buffer_allocator = allocator;
    v8::Isolate *isolate = v8::Isolate::New(isolateCreateParams);
    isolate->Enter();
    v8::internal::Isolate *i_isolate = reinterpret_cast<v8::internal::Isolate*>(isolate);
    v8::HandleScope scope(isolate);
    auto alloc = i_isolate->allocator();

    v8::Context::New(isolate)->Enter();
    v8::internal::Zone zone(alloc, MY_ZONE_NAME);


    //
    // Done initialization.
    // Begin constructing and dumping the Code
    //

    v8::internal::Handle<v8::internal::String> pattern = (
        i_isolate->factory()
                 ->NewStringFromUtf8(
                     v8::internal::CStrVector(args.target_regex.c_str())
                )
    ).ToHandleChecked();
    
    v8::internal::JSRegExp::Flags flags = v8::internal::JSRegExp::kNone;

    cout << "Beginning compilation" << endl;

    if (args.target == regulator::kByteCode)
    {
        cout << "Targeting bytecode" << endl;

        v8::internal::FLAG_regexp_interpret_all = true;
        v8::internal::Handle<v8::internal::JSRegExp> regexp = (
            v8::internal::JSRegExp::New(i_isolate, pattern, flags)
        ).ToHandleChecked();
        v8::internal::Handle<v8::internal::Object> o = v8::internal::RegExp::Compile(
                i_isolate, regexp, pattern, flags, 0
        ).ToHandleChecked();
        if (regexp->TypeTag() == v8::internal::JSRegExp::Type::ATOM)
        {
            cerr << "Type is atom; compilation not possible" << endl;
            exit(2);
        }
        else if (regexp->TypeTag() == v8::internal::JSRegExp::Type::IRREGEXP)
        {
            cout << "Type is irregexp" << endl;
        }
        else
        {
            cerr << "Unknown type" << endl;
            exit(2);
        }

        // I would love to be able to call RegExpImpl::EnsureCompiledIrregexp but it isn't
        // exposed in a header. Instead, I'll just make it match against a string and expect
        // code-gen to be run.

        // This encodes the snowman emoji as a string. Done to force utf-8,
        // otherwise the regexp will compile to latin1
        v8::internal::Handle<v8::internal::String> subject = (
        i_isolate->factory()
                ->NewStringFromUtf8(
                    v8::internal::CStrVector("\xE2\x98\x83")
                )
        ).ToHandleChecked();

        int capture_count = regexp->CaptureCount();
        v8::internal::Handle<v8::internal::RegExpMatchInfo> match_info =
            v8::internal::RegExpMatchInfo::New(i_isolate, capture_count);

        v8::internal::Handle<v8::internal::Object> o2 = v8::internal::RegExp::Exec(
            i_isolate, regexp, subject, 0, match_info).ToHandleChecked();
        o2->Print(cout);

        // ok it should be bytecode-compiled now
        v8::internal::Object bytecode_obj = regexp->Bytecode(false);
        cout << "Is Smi? " << bytecode_obj.IsSmi() << endl;

        v8::internal::ByteArray ba = v8::internal::ByteArray::cast(regexp->Bytecode(false));

        cout << "Got BA" << endl;

        // annoying -- the below is usually inlined, but I can't get the header to include here
        // without significant effort
        uint8_t *pc_start = ba.GetDataStartAddress();
        cout << "Got PC Start: 0x" << std::hex << (uintptr_t)(pc_start) << endl;
        ba.Print(cout);

        size_t length = ba.length();

        cout << "Emitting code to " << args.output_file_name << endl;

        // now output to file
        ofstream outfile;
        outfile.open(args.output_file_name, ios::out | ios::binary);
        outfile.write((const char *)pc_start, length);
        outfile.close();
    }
}
