#include "src/execution/isolate.h"

#include "fuzz/corpus.hpp"
#include "fuzz/mutator.hpp"
#include "fuzz-driver.hpp"
#include "regexp-executor.hpp"
#include "flags.hpp"
#include "timer.hpp"

#include <cstring>
#include <random>
#include <chrono>
#include <iostream>
#include <iomanip>

namespace f = regulator::flags;

namespace regulator
{
namespace fuzz
{

static const size_t N_CHILDREN_PER_PARENT = 100;


typedef struct {
    std::chrono::steady_clock::time_point begin;
    std::chrono::steady_clock::time_point deadline;
    std::chrono::steady_clock::time_point last_screen_render;
    Corpus *corpus;
    CorpusEntry *worst_known_case;
    bool exit_requested;
} exec_context;


/**
 * A work-interrupt point, where we update some meta-information,
 * like rendering output or toggling exit_requested for timeouts
 */
inline void work_interrupt(exec_context &ctx)
{
    // First, re-check for for timeout
    auto now = std::chrono::steady_clock::now();
    ctx.exit_requested = now >= ctx.deadline;

    // Print stuff to screen if we haven't done that lately
    if ((now - ctx.last_screen_render) > std::chrono::milliseconds(500))
    {
        auto elapsed = now - ctx.begin;
        double seconds_elapsed = elapsed.count() / (static_cast<double>(std::nano::den));
        std::cout << "Elapsed: " << std::setprecision(5) << std::setw(4) << seconds_elapsed << " ";

        std::cout << "Corpus Size: " << ctx.corpus->Size() << " ";

        std::cout << "Slowest: " << ctx.worst_known_case->ToString() << std::endl;

        if (f::FLAG_debug)
        {
            std::cout << "DEBUG corpus mem=";
            
            // Print memory footprint in more readable units (kb, mb, etc...)
            size_t mem_footprint = ctx.corpus->MemoryFootprint();

            if (mem_footprint <= 1024)
            {
                std::cout << mem_footprint << "b ";
            }
            else if (mem_footprint <= 1024 * 1024)
            {
                std::cout << (mem_footprint / 1024) << "kb ";
            }
            else if (mem_footprint <= 1024 * 1024 * 1024)
            {
                std::cout << (mem_footprint / (1024 * 1024)) << "mb ";
            }
            else
            {
                std::cout << (mem_footprint / (1024 * 1024 * 1024)) << "gb ";
            }

            // Print the residency of the upper-bound coverage map
            double residency = ctx.corpus->Residency() * 100;
            std::cout << "residency=";
            std::cout << std::setprecision(4) << std::setw(5) << std::setfill(' ') << residency;
            std::cout << std::setw(0) << "%" << std::endl;
        }

        ctx.last_screen_render = now;
    }
}


uint64_t Fuzz(
    v8::Isolate *isolate,
    regulator::executor::V8RegExp *regexp,
    uint8_t *outbuf, size_t strlen)
{
    exec_context context;
    
    // Set up context (used at work-interrupt points)
    Corpus corpus;
    context.begin = std::chrono::steady_clock::now();
    context.deadline = context.begin + std::chrono::seconds(regulator::flags::FLAG_timeout);
    context.corpus = &corpus;
    context.exit_requested = false;
    
    // for some reason ::min() causes some overflows that are annoying to handle
    context.last_screen_render = context.begin - std::chrono::hours(10000);
    
    // Baseline: seed the corpus with 'aaaaaaa...'
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

    context.worst_known_case = new CorpusEntry(*baseline_entry);


    if (f::FLAG_debug)
    {
        std::cout << "DEBUG Baseline established. Proceeding to main work loop." << std::endl;
    }

    std::vector<CorpusEntry *> new_children;
    std::vector<uint8_t *> children;

    for (size_t num_generations=0; !context.exit_requested; num_generations++)
    {
        work_interrupt(context);

        // Iterate over each item in the corpus
        for (size_t i=0; i < corpus.Size() && !context.exit_requested; i++)
        {
            CorpusEntry * parent = corpus.Get(i);

            // Choose whether to use this entry as a parent
            
            // alpha = prob(selected) * 1024 - 1
            uint64_t alpha = 9; // approx. 1%
            if (corpus.MaximizesUpperBound(parent->GetCoverageTracker()))
            {
                alpha = 1024 - 1;
            }

            if (random() & (1024 - 1) > alpha)
            {
                // This entry was NOT selected to be a parent
                continue;
            }

            // Create children
            GenChildren(&corpus, i, N_CHILDREN_PER_PARENT, children);

            // Evaluate each child
            for (size_t j = 0; j < children.size() && !context.exit_requested; j++)
            {
                uint8_t *child = children[j];

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
                if (
                        parent->GetCoverageTracker()->HasNewPath(result.coverage_tracker) &&
                        !corpus.IsRedundant(result.coverage_tracker)
                    )
                {
                    new_children.push_back(new CorpusEntry(
                        child,
                        strlen,
                        new CoverageTracker(*result.coverage_tracker)
                    ));

                    if (result.coverage_tracker->Total() >
                            context.worst_known_case->GetCoverageTracker()->Total())
                    {
                        // this is the new known-worst-case
                        delete context.worst_known_case;
                        uint8_t *newbuf = new uint8_t[strlen];
                        memcpy(newbuf, child, strlen);
                        context.worst_known_case = new CorpusEntry(
                            newbuf,
                            strlen,
                            new CoverageTracker(*result.coverage_tracker)
                        );
                    }
                }
                // Otherwise, no new behavior was discovered, delete the memory
                else
                {
                    delete[] child;
                }
            }

            children.clear();
            work_interrupt(context);
        }

        // record new children into corpus
        for (size_t j=0; j<new_children.size(); j++)
        {
            corpus.Record(new_children[j]);
        }
        new_children.clear();

        corpus.Economize();
        // if (num_generations & (4 - 1) == 0)
        // {
        // }

        // std::cout << "Corpus size: " << corpus.Size() << std::endl;
        // CorpusEntry *most_good = corpus.MaxOpcount();
        // std::cout << "Most good: " << most_good->ToString() << std::endl;
        // CorpusEntry *arbitrary = corpus.GetOne();
        // std::cout << "Sample: " << arbitrary->ToString() << std::endl;
    }

    delete[] baseline;

    return corpus.MaxOpcount()->coverage_tracker->Total();
}

}

}
