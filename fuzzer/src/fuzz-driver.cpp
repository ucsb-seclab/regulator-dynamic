#include "src/execution/isolate.h"

#include "fuzz/corpus.hpp"
#include "fuzz/mutator.hpp"
#include "fuzz-driver.hpp"
#include "regexp-executor.hpp"
#include "flags.hpp"

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


/**
 * Contains context about the active fuzzing campaign, used for convenience
 * when calling the work_interrupt procedure.
 */
typedef struct {
#ifdef REG_PROFILE
    /**
     * Amount of time spent executing regexp since last render
     */
    std::chrono::steady_clock::duration exec_dur;

    /**
     * Amount of time spent generating children since last render
     */
    std::chrono::steady_clock::duration gen_child_dur;

    /**
     * Amount of time spent economizing the corpus
     */
    std::chrono::steady_clock::duration econo_dur;
#endif // REG_PROFILE

    /**
     * When the fuzzing campaign began
     */
    std::chrono::steady_clock::time_point begin;
    /**
     * When the fuzzing campaign must exit
     */
    std::chrono::steady_clock::time_point deadline;
    /**
     * When the last screen render occurred
     */
    std::chrono::steady_clock::time_point last_screen_render;
    /**
     * The number of regular expression executions which
     * took place since last screen render
     */
    uintmax_t executions_since_last_render;
    /**
     * The Corpus in use (helpful for printing size, mem, etc)
     */
    Corpus *corpus;
    /**
     * The input which triggers the longest-known execution path
     */
    CorpusEntry *worst_known_case;
    /**
     * When true the fuzzing loop should exit as soon as possible
     */
    bool exit_requested;
} exec_context;


/**
 * A work-interrupt point, where we update some meta-information,
 * like rendering output or toggling exit_requested for timeouts
 */
inline void work_interrupt(exec_context &ctx)
{
    // First, re-check for for deadline
    auto now = std::chrono::steady_clock::now();
    ctx.exit_requested = now >= ctx.deadline;

    // Print stuff to screen if we haven't done that lately
    if ((now - ctx.last_screen_render) > std::chrono::milliseconds(500))
    {
        auto elapsed = now - ctx.begin;
        double seconds_elapsed = elapsed.count() / (static_cast<double>(std::nano::den));

        auto elapsed_since_last_render = now - ctx.last_screen_render;
        double seconds_elapsed_since_last_render = elapsed_since_last_render.count() / (static_cast<double>(std::nano::den));
        double execs_per_second = ctx.executions_since_last_render / seconds_elapsed_since_last_render;

        std::cout << "Elapsed: "
            << std::setprecision(5) << std::setw(4) << seconds_elapsed << " "
            << std::setw(0);

        std::cout << "Corpus Size: " << ctx.corpus->Size() << " ";

        std::cout << "Slowest: " << ctx.worst_known_case->ToString() << " ";

        std::cout << "Executions/s: "
            << std::setprecision(5) << std::setw(4) << execs_per_second << " "
            << std::setw(0) << std::endl;

#ifdef REG_PROFILE
        // Print and reset profiling stats
        double seconds_exec = ctx.exec_dur.count() / static_cast<double>(std::nano::den);
        double seconds_gen_child = ctx.gen_child_dur.count() / static_cast<double>(std::nano::den);
        double seconds_econo = ctx.econo_dur.count() / static_cast<double>(std::nano::den);

        std::cout << std::setprecision(7) << std::setw(0)
                  << "Exec: " << seconds_exec << " "
                  << "GenChild: " << seconds_gen_child << " "
                  << "Econo: " << seconds_econo << " "
                  << "Other: " << (seconds_elapsed_since_last_render - (seconds_exec + seconds_gen_child + seconds_econo))
                  << std::endl;
        
        ctx.exec_dur = std::chrono::steady_clock::duration::zero();
        ctx.gen_child_dur = std::chrono::steady_clock::duration::zero();
        ctx.econo_dur = std::chrono::steady_clock::duration::zero();
#endif

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
        ctx.executions_since_last_render = 0;
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
    context.executions_since_last_render = 0;
    
    // for some reason std::chrono::...::min() causes some overflows that are annoying to handle
    context.last_screen_render = context.begin - std::chrono::hours(10000);
    
    // Baseline: seed the corpus with 'aaaaaaa...'
    uint8_t *baseline = new uint8_t[strlen];
    memset(baseline, 'a', strlen);

    regulator::executor::V8RegExpResult result;
    regulator::executor::Result result_code = regulator::executor::Exec(
        regexp,
        baseline,
        strlen, &result,
        regulator::executor::kOnlyOneByte
    );

    if (result_code != regulator::executor::kSuccess)
    {
        std::cerr << "Baseline execution failed!!!" << std::endl;
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
#ifdef REG_PROFILE
            std::chrono::steady_clock::time_point gen_start = std::chrono::steady_clock::now();
#endif
            GenChildren(&corpus, i, N_CHILDREN_PER_PARENT, children);
#ifdef REG_PROFILE
            context.gen_child_dur += (std::chrono::steady_clock::now() - gen_start);
#endif

            // Evaluate each child
            for (size_t j = 0; j < children.size() && !context.exit_requested; j++)
            {
                uint8_t *child = children[j];

#ifdef REG_PROFILE
                std::chrono::steady_clock::time_point exec_start = std::chrono::steady_clock::now();
#endif
                result_code = regulator::executor::Exec(
                    regexp,
                    child,
                    strlen,
                    &result,
                    regulator::executor::kOnlyOneByte
                );

#ifdef REG_PROFILE
                context.exec_dur += (std::chrono::steady_clock::now() - exec_start);
#endif

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

                // Execution succeeded, proceed to analyze how 'good' this was
                context.executions_since_last_render++;

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

#ifdef REG_PROFILE
        std::chrono::steady_clock::time_point econo_start = std::chrono::steady_clock::now();
#endif
        corpus.Economize();
#ifdef REG_PROFILE
        context.econo_dur += (std::chrono::steady_clock::now() - econo_start);
#endif
    }

    return corpus.MaxOpcount()->coverage_tracker->Total();
}

}

}
