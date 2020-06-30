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

static const size_t N_CHILDREN_PER_PARENT = 100;


uint64_t Fuzz(
    v8::Isolate *isolate,
    regulator::executor::V8RegExp *regexp,
    uint8_t *outbuf, size_t strlen)
{
    Corpus corpus;
    
    // baseline: start with a string of random bytes
    uint8_t *baseline = new uint8_t[strlen];
    memset(baseline, 'a', strlen);

    regulator::executor::V8RegExpResult result;
    regulator::executor::Result result_code = regulator::executor::Exec(
        regexp,
        reinterpret_cast<char *>(baseline), strlen, &result
    );

    if (result_code != regulator::executor::kSuccess)
    {
        std::cerr << "Baseline execution failed!!!" << std::endl;
        std::cerr << (result_code == regulator::executor::kNotValidUtf8) << std::endl;
        return 0;
    }

    CorpusEntry *baseline_entry = new CorpusEntry(baseline, strlen, new CoverageTracker(*result.coverage_tracker));

    corpus.Record(baseline_entry);

    uint8_t *tmp_fuzz_buff = new uint8_t[strlen];

    std::vector<CorpusEntry *> new_children;
    std::vector<uint8_t *> children;

    for (size_t i=0; i<1024; i++)
    {
        // Iterate over each item in the corpus
        for (size_t j=0; j < corpus.Size(); j++)
        {
            CorpusEntry * parent = corpus.Get(j);

            // Choose whether to use this entry as a parent
            
            // alpha = prob(selected) * 1024 - 1
            uint64_t alpha = 9; // approx. 1%
            if (corpus.MaximizesUpperBound(parent->coverage_tracker))
            {
                alpha = 1024 - 1;
            }

            if (random() & (1024 - 1) > alpha)
            {
                // This entry was NOT selected to be a parent
                continue;
            }

            // Create children
            GenChildren(&corpus, j, N_CHILDREN_PER_PARENT, children);

            // Evaluate each child
            for (size_t k = 0; k < children.size(); k++)
            {
                uint8_t *child = children[k];

                result_code = regulator::executor::Exec(
                    regexp,
                    (char *)(child),
                    strlen,
                    &result,
                    regulator::executor::kOnlyOneByte
                );

                if (result_code == regulator::executor::kBadStrRepresentation)
                {
                    // child mutated to a two-byte representation, skip it for now
                    continue;
                }

                if (result_code != regulator::executor::kSuccess)
                {
                    std::cerr << "execution failed!!!" << std::endl;
                    return 0;
                }

                // If this child uncovered new behavior, then add it to new_children
                // (later added to corpus, which assumes ownership)
                if (corpus.HasNewPath(result.coverage_tracker))
                {
                    new_children.push_back(new CorpusEntry(
                        child,
                        strlen,
                        new CoverageTracker(*result.coverage_tracker)
                    ));
                }
                // Otherwise, no new behavior was discovered, delete the memory
                else
                {
                    delete[] child;
                }
            }

            children.clear();
        }

        // record new children into corpus
        for (size_t k=0; k<new_children.size(); k++)
        {
            corpus.Record(new_children[k]);
        }
        new_children.clear();

        std::cout << "Corpus size: " << corpus.Size() << std::endl;
        CorpusEntry *most_good = corpus.MaxOpcount();
        std::cout << "Most good: " << most_good->ToString() << std::endl;
        CorpusEntry *arbitrary = corpus.GetOne();
        std::cout << "Sample: " << arbitrary->ToString() << std::endl;

        if ((i & (0x4 - 1)) == 0)
        {
            std::cout << "Compacting" << std::endl;
            corpus.Economize();
        }
    }

    delete[] baseline;
    delete[] tmp_fuzz_buff;

    return result.opcount;
}

}

}
