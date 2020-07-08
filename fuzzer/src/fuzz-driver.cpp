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
     * The one-byte corpus in use (helpful for printing size, mem, etc)
     */
    Corpus<uint8_t> *corpus_one_byte;
    /**
     * The two-byte corpus in use
     */
    Corpus<uint16_t> *corpus_two_byte;
    /**
     * The input which triggers the longest-known execution path
     */
    CorpusEntry<uint8_t> *worst_known_case_one_byte;
    /**
     * The input which triggers the longest-known execution path
     */
    CorpusEntry<uint16_t> *worst_known_case_two_byte;
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

        std::cout << "Executions/s: "
            << std::setprecision(5) << std::setw(4) << execs_per_second << " "
            << std::setw(0) << std::endl;

        std::cout << "1-byte Corpus Size: " << ctx.corpus_one_byte->Size() << " ";

        std::cout << "Slowest(1-byte): " << ctx.worst_known_case_one_byte->ToString() << std::endl;

        std::cout << "2-byte Corpus Size: " << ctx.corpus_two_byte->Size() << " ";

        std::cout << "Slowest(2-byte): " << ctx.worst_known_case_two_byte->ToString() << std::endl;

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
            size_t mem_footprint = ctx.corpus_one_byte->MemoryFootprint() +
                                   ctx.corpus_two_byte->MemoryFootprint();

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
            double residency_1 = ctx.corpus_one_byte->Residency() * 100;
            double residency_2 = ctx.corpus_two_byte->Residency() * 100;
            std::cout << "residency(1-byte)=";
            std::cout << std::setprecision(4) << std::setw(5) << std::setfill(' ') << residency_1;
            std::cout << "% residency(2-byte)=" << residency_2;
            std::cout << std::setw(0) << "%" << std::endl;
        }

        ctx.last_screen_render = now;
        ctx.executions_since_last_render = 0;
    }
}


/**
 * Seed the corpus, returns true on success
 */
template<typename Char>
inline bool seed_corpus(
    Corpus<Char> *corpus,
    regulator::executor::V8RegExp *regexp,
    size_t strlen)
{
    Char *baseline = new Char[strlen];
    for (size_t i=0; i<strlen; i++)
    {
        baseline[i] = 'a';
    }

    // we need to execute them to get the initial coverage tracker
    regulator::executor::V8RegExpResult result;
    regulator::executor::Result result_code = regulator::executor::Exec(
        regexp,
        baseline,
        strlen,
        &result,
        regulator::executor::kOnlyOneByte
    );

    if (result_code != regulator::executor::kSuccess)
    {
        std::cout << "Baseline execution failed for 1-byte!!!" << std::endl;
        return false;
    }

    CorpusEntry<Char> *entry = new CorpusEntry<Char>(
        baseline,
        strlen,
        new CoverageTracker(*result.coverage_tracker)
    );

    // this will be deleted later
    result.coverage_tracker = nullptr;

    corpus->Record(entry);
    return true;
}


/**
 * Evaluate a child solution on a given regexp and evaluate
 * whether it is worth keeping. If so the new CorpusEntry
 * is returned, and the known-worst entry is updated.
 */
template<typename Char>
inline bool evaluate_child(
    exec_context &context,
    Char *child,
    size_t &strlen,
    regulator::executor::V8RegExp *regexp,
    Corpus<Char> &corpus,
    CorpusEntry<Char> *parent,
    CorpusEntry<Char> *&out)
{
    regulator::executor::V8RegExpResult result;

#ifdef REG_PROFILE
    std::chrono::steady_clock::time_point exec_start = std::chrono::steady_clock::now();
#endif
    regulator::executor::Result result_code = regulator::executor::Exec(
        regexp,
        child,
        strlen,
        &result,
        regulator::executor::kOnlyOneByte
    );

#ifdef REG_PROFILE
    context.exec_dur += (std::chrono::steady_clock::now() - exec_start);
#endif

    if (result_code == regulator::executor::kSuccess)
    {
        // Execution succeeded, proceed to analyze how 'good' this was
        context.executions_since_last_render++;

        // If this child uncovered new behavior, then add it to new_children
        // (later added to corpus, which assumes ownership)
        if (
                parent->GetCoverageTracker()->HasNewPath(result.coverage_tracker) &&
                !corpus.IsRedundant(result.coverage_tracker)
            )
        {
            out = new CorpusEntry<Char>(
                child,
                strlen,
                new CoverageTracker(*result.coverage_tracker)
            );

            result.coverage_tracker = nullptr;
            return true;
        }
    }

    delete[] child;
    result.coverage_tracker = nullptr;
    return false;
}


/**
 * Pass over the given Corpus exactly once
 */
template<typename Char>
inline void pass_corpus_once(
    exec_context &context,
    regulator::executor::V8RegExp *regexp,
    size_t &strlen,
    Corpus<Char> &corpus,
    CorpusEntry<Char> *&worst_known)
{
    std::vector<CorpusEntry<Char> *> new_children;
    std::vector<Char *> children_to_eval;

    for (size_t i=0; i < corpus.Size() && !context.exit_requested; i++)
    {
        CorpusEntry<Char> * parent = corpus.Get(i);

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
        children_to_eval.clear();
        GenChildren<Char>(&corpus, i, N_CHILDREN_PER_PARENT, children_to_eval);
#ifdef REG_PROFILE
        context.gen_child_dur += (std::chrono::steady_clock::now() - gen_start);
#endif

        // Evaluate each child
        for (size_t j = 0; j < children_to_eval.size() && !context.exit_requested; j++)
        {
            Char *child = children_to_eval[j];
            CorpusEntry<Char> *entry = nullptr;
            if (evaluate_child<Char>(
                    context,
                    child,
                    strlen,
                    regexp,
                    corpus,
                    parent,
                    entry))
            {
                new_children.push_back(entry);

                if (entry->GetCoverageTracker()->Total() >
                        worst_known->GetCoverageTracker()->Total())
                {
                    // this is the new known-worst-case, remove old one
                    delete worst_known;
                    Char *newbuf = new Char[strlen];
                    memcpy(newbuf, child, strlen * sizeof(Char));
                    worst_known = new CorpusEntry<Char>(
                        newbuf,
                        strlen,
                        new CoverageTracker(*entry->GetCoverageTracker())
                    );
                }
            }
        }
    }

    // record new children into corpus
    for (size_t j=0; j<new_children.size(); j++)
    {
        corpus.Record(new_children[j]);
    }

#ifdef REG_PROFILE
    std::chrono::steady_clock::time_point econo_start = std::chrono::steady_clock::now();
#endif
    corpus.Economize();
#ifdef REG_PROFILE
    context.econo_dur += (std::chrono::steady_clock::now() - econo_start);
#endif
}


uint64_t Fuzz(
    v8::Isolate *isolate,
    regulator::executor::V8RegExp *regexp,
    size_t strlen)
{
    exec_context context;

    // Set up context (used at work-interrupt points)
    Corpus<uint8_t> corpus_one_byte;
    Corpus<uint16_t> corpus_two_byte;
    context.begin = std::chrono::steady_clock::now();
    context.deadline = context.begin + std::chrono::seconds(regulator::flags::FLAG_timeout);
    context.corpus_one_byte = &corpus_one_byte;
    context.corpus_two_byte = &corpus_two_byte;
    context.exit_requested = false;
    context.executions_since_last_render = 0;

    // for some reason std::chrono::...::min() causes some overflows that are annoying to handle
    context.last_screen_render = context.begin - std::chrono::hours(10000);

    if (!seed_corpus(&corpus_one_byte, regexp, strlen))
    {
        return 0;
    }
    if (!seed_corpus(&corpus_two_byte, regexp, strlen))
    {
        return 0;
    }

    context.worst_known_case_one_byte = new CorpusEntry<uint8_t>(
        *corpus_one_byte.Get(0));
    context.worst_known_case_two_byte = new CorpusEntry<uint16_t>(
        *corpus_two_byte.Get(0));

    if (f::FLAG_debug)
    {
        std::cout << "DEBUG Baseline established. Proceeding to main work loop." << std::endl;
    }

    std::vector<CorpusEntry<uint8_t> *> new_children_one_byte;
    std::vector<CorpusEntry<uint16_t> *> new_children_two_byte;
    std::vector<uint8_t *> children_buf_one_byte;
    std::vector<uint16_t *> children_buf_two_byte;

    for (size_t num_generations=0; !context.exit_requested; num_generations++)
    {
        if (f::FLAG_debug)
        {
            std::cout << "DEBUG evaling generation " << num_generations << std::endl;
        }
        work_interrupt(context);

        pass_corpus_once<uint8_t>(
            context,
            regexp,
            strlen,
            corpus_one_byte,
            context.worst_known_case_one_byte
        );

        pass_corpus_once<uint16_t>(
            context,
            regexp,
            strlen,
            corpus_two_byte,
            context.worst_known_case_two_byte
        );
    }

    return 1;
}

}

}
