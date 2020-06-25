#include "src/execution/isolate.h"

#include "fuzz/corpus.hpp"
#include "fuzz/mutator.hpp"
#include "fuzz-driver.hpp"
#include "regexp-executor.hpp"

#include <cstring>
#include <random>
#include <iostream>

namespace regulator
{
namespace fuzz
{

void print_helper(uint8_t *buf, size_t strlen)
{
    // prints to cout
    for (size_t i=0; i<strlen; i++)
    {
        char c = buf[i];
        if ( ' ' <= c && c <= '~' )
        {
            std::cout << c;
        }
        else
        {
            std::cout << "\\x" << std::hex << static_cast<uint16_t>(buf[i]) << std::dec;
        }
    }
}


uint64_t Fuzz(
    v8::Isolate *isolate,
    regulator::executor::V8RegExp *regexp,
    uint8_t *outbuf, size_t strlen)
{
    Corpus corpus;
    
    // baseline: start with a string of random bytes
    uint8_t *baseline = new uint8_t[strlen];
    for (size_t i = 0; i < strlen; i++)
    {
        baseline[i] = static_cast<uint8_t>(random());
    }

    regulator::executor::V8RegExpResult result;
    regulator::executor::Result result_code = regulator::executor::Exec(
        regexp,
        reinterpret_cast<char *>(baseline), strlen, &result
    );

    if (result_code != regulator::executor::kSuccess)
    {
        std::cerr << "Baseline execution failed!!!" << std::endl;
        return 0;
    }

    CorpusEntry *baseline_entry = new CorpusEntry(baseline, strlen, result.opcount, result.coverage_tracker);

    corpus.Record(baseline_entry);

    uint8_t *tmp_fuzz_buff = new uint8_t[strlen];
    for (size_t i=0; i<1024; i++)
    {
        for (size_t j=0; j<(1024 * 2); j++)
        {
            // get parent
            CorpusEntry *input = corpus.GetOne();

            // create child
            memcpy(tmp_fuzz_buff, input->buf, strlen);
            havoc_random_byte(tmp_fuzz_buff, strlen);
            
            // print_helper(tmp_fuzz_buff, strlen);
            // std::cout << std::endl;
            
            // execute
            result_code = regulator::executor::Exec(
                regexp,
                reinterpret_cast<char *>(tmp_fuzz_buff), strlen, &result
            );

            if (result_code != regulator::executor::kSuccess)
            {
                std::cerr << "execution failed!!!" << std::endl;
                return 0;
            }

            // record into corpus
            CorpusEntry *new_entry = new CorpusEntry(tmp_fuzz_buff, strlen, result.opcount, result.coverage_tracker);

            corpus.Record(new_entry);
        }

        CorpusEntry *most_good = corpus.MostGood();
        std::cout << "(" << i << ") -> " << most_good->Goodness();
        print_helper(most_good->buf, most_good->buflen);
        std::cout << std::endl;
    }

    delete[] baseline;
    delete[] tmp_fuzz_buff;

    return result.opcount;
}

}

}
