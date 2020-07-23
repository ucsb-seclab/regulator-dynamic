#include "src/execution/isolate.h"

#include "fuzz-driver.hpp"

#include "fuzz/corpus.hpp"
#include "fuzz/work-queue.hpp"

#include "regexp-executor.hpp"
#include "interesting-char-finder.hpp"
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

static const size_t N_CHILDREN_PER_PARENT = 50;


/**
 * Represents the in-progress information about a fuzzing campaign.
 */
template<typename Char>
class FuzzCampaign
{
public:
    FuzzCampaign()
        : corpus(new Corpus<Char>()),
          executions_since_last_render(0),
          num_generations(0),
          work_queue(new Queue<Char>())
        {};
    ~FuzzCampaign()
    {
        delete this->corpus;
        delete this->work_queue;
    }
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
     * The active Corpus for this campaign
     */
    Corpus<Char> *corpus;

    /**
     * The number of regular expression executions which
     * took place since last screen render
     */
    uintmax_t executions_since_last_render;

    /**
     * The number of generation rounds completed
     */
    uintmax_t num_generations;

    /**
     * The queue of parents to fuzz
     */
    regulator::fuzz::Queue<Char> *work_queue;

    /**
     * The time at which fuzz work should yield for other work
     */
    std::chrono::steady_clock::time_point yield_deadline;
};


/**
 * Contains context about the entire active fuzzing campaign
 */
typedef struct {
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
     * The one-byte campaign details
     */
    FuzzCampaign<uint8_t> *campaign_one_byte;
    /**
     * The two-byte campaign details
     */
    FuzzCampaign<uint16_t> *campaign_two_byte;
    /**
     * When true, the fuzzing loop should exit as soon as possible
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

        std::cout << "Elapsed: "
            << std::setprecision(5) << std::setw(4) << seconds_elapsed << " "
            << std::setw(0) << std::endl;

        auto elapsed_since_last_render = now - ctx.last_screen_render;
        double seconds_elapsed_since_last_render = elapsed_since_last_render.count() / (static_cast<double>(std::nano::den));

        if (ctx.campaign_one_byte != nullptr)
        {
            FuzzCampaign<uint8_t> *campaign = ctx.campaign_one_byte;
            double execs_per_second = campaign->executions_since_last_render / seconds_elapsed_since_last_render;
            std::cout << "1-byte summary: "
                << "Exec/s: "
                << std::setprecision(5) << std::setw(4) << execs_per_second << " "
                << std::setw(0)
                << "Corpus Size: " << campaign->corpus->Size() << " "
                << "Slowest(1-byte): " << campaign->corpus->MaxOpcount()->ToString()
                << std::endl;

            campaign->executions_since_last_render = 0;
        }

        if (ctx.campaign_two_byte != nullptr)
        {
            FuzzCampaign<uint16_t> *campaign = ctx.campaign_two_byte;
            double execs_per_second = campaign->executions_since_last_render / seconds_elapsed_since_last_render;
            std::cout << "2-byte summary: "
                << "Exec/s: "
                << std::setprecision(5) << std::setw(4) << execs_per_second << " "
                << std::setw(0)
                << "Corpus Size: " << campaign->corpus->Size() << " "
                << "Slowest(2-byte): " << campaign->corpus->MaxOpcount()->ToString()
                << std::endl;

            campaign->executions_since_last_render = 0;
        }

#ifdef REG_PROFILE
        // Print and reset profiling stats. VERY UGLY.
        double seconds_exec = 0;
        double seconds_gen_child = 0;
        double seconds_econo = 0;

        if (ctx.campaign_one_byte != nullptr)
        {
            seconds_exec += ctx.campaign_one_byte->exec_dur.count()
                / static_cast<double>(std::nano::den);
            seconds_gen_child += ctx.campaign_one_byte->gen_child_dur.count()
                / static_cast<double>(std::nano::den);
            seconds_econo += ctx.campaign_one_byte->econo_dur.count()
                / static_cast<double>(std::nano::den);
            
            ctx.campaign_one_byte->gen_child_dur =
                ctx.campaign_one_byte->exec_dur =
                ctx.campaign_one_byte->econo_dur =
                    std::chrono::steady_clock::duration::zero();
        }

        if (ctx.campaign_two_byte != nullptr)
        {
            seconds_exec += ctx.campaign_two_byte->exec_dur.count()
                / static_cast<double>(std::nano::den);
            seconds_gen_child += ctx.campaign_two_byte->gen_child_dur.count()
                / static_cast<double>(std::nano::den);
            seconds_econo += ctx.campaign_two_byte->econo_dur.count()
                / static_cast<double>(std::nano::den);
            
            ctx.campaign_two_byte->gen_child_dur =
                ctx.campaign_two_byte->exec_dur =
                ctx.campaign_two_byte->econo_dur =
                    std::chrono::steady_clock::duration::zero();
        }

        std::cout << std::setprecision(7) << std::setw(0)
                  << "Exec: " << seconds_exec << " "
                  << "GenChild: " << seconds_gen_child << " "
                  << "Econo: " << seconds_econo << " "
                  << "Other: " << (seconds_elapsed_since_last_render - (seconds_exec + seconds_gen_child + seconds_econo))
                  << std::endl;
#endif

        if (f::FLAG_debug)
        {
            std::cout << "DEBUG corpus mem=";

            // Print memory footprint in more readable units (kb, mb, etc...)
            size_t mem_footprint = 0;
            if (ctx.campaign_one_byte != nullptr)
            {
                mem_footprint += ctx.campaign_one_byte->corpus->MemoryFootprint();
            }
            if (ctx.campaign_two_byte != nullptr)
            {
                mem_footprint += ctx.campaign_two_byte->corpus->MemoryFootprint();
            }

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
            if (ctx.campaign_one_byte != nullptr)
            {
                double residency_1 = ctx.campaign_one_byte->corpus->Residency() * 100;
                std::cout << "residency(1-byte)=";
                std::cout << std::setprecision(4) << std::setw(5) << std::setfill(' ') << residency_1
                    << "% ";
            }
            if (ctx.campaign_two_byte != nullptr)
            {
                double residency_2 = ctx.campaign_two_byte->corpus->Residency() * 100;
                std::cout << "residency(2-byte)=" << residency_2;
                std::cout << "%";
            }
            std::cout << std::setw(0) << std::endl;
        }

        ctx.last_screen_render = now;
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
    corpus->FlushGeneration();
    return true;
}


/**
 * Evaluate a child solution on a given regexp and evaluate
 * whether it is worth keeping. If so the new CorpusEntry
 * is returned, and the known-worst entry is updated.
 */
template<typename Char>
inline void evaluate_child(
    exec_context &context,
    Char *child,
    size_t &strlen,
    regulator::executor::V8RegExp *regexp,
    FuzzCampaign<Char> *campaign,
    CorpusEntry<Char> *parent)
{
    regulator::executor::V8RegExpResult result;

#ifdef REG_PROFILE
    std::chrono::steady_clock::time_point exec_start = std::chrono::steady_clock::now();
#endif
    constexpr auto enforce_encoding =
        sizeof(Char) == 1
        ? regulator::executor::kOnlyOneByte
        : regulator::executor::kOnlyTwoByte;

    regulator::executor::Result result_code = regulator::executor::Exec(
        regexp,
        child,
        strlen,
        &result,
        enforce_encoding
    );

#ifdef REG_PROFILE
    campaign->exec_dur += (std::chrono::steady_clock::now() - exec_start);
#endif

    if (result_code == regulator::executor::kSuccess)
    {
        // Execution succeeded, proceed to analyze how 'good' this was
        campaign->executions_since_last_render++;

        // If this child uncovered new behavior, then add it to new_children
        // (later added to corpus, which assumes ownership)
        if (
                parent->GetCoverageTracker()->HasNewPath(result.coverage_tracker) &&
                !campaign->corpus->IsRedundant(result.coverage_tracker)
            )
        {
            campaign->corpus->Record(
                new CorpusEntry<Char>(
                    child,
                    strlen,
                    new CoverageTracker(*result.coverage_tracker)
                )
            );

            // avoids double free, but we should probably make the V8ExecResult
            // not call delete on the coverage tracker to avoid having to do this...
            result.coverage_tracker = nullptr;
            return;
        }
    }

    delete[] child;
    result.coverage_tracker = nullptr;
    return;
}


/**
 * Pass over the given Corpus exactly once
 */
template<typename Char>
inline void work_on_corpus(
    exec_context &context,
    regulator::executor::V8RegExp *regexp,
    size_t &strlen,
    FuzzCampaign<Char> *campaign)
{

    // TODO this can be made an array if we're only generating a
    // fixed-length number of children
    std::vector<Char *> children_to_eval;

    for (;std::chrono::steady_clock::now() < campaign->yield_deadline;)
    {
        // If we've already fuzzed everything in the queue, flush and
        // re-build the queue
        if (!campaign->work_queue->HasNext())
        {
#ifdef REG_PROFILE
            std::chrono::steady_clock::time_point econo_start = std::chrono::steady_clock::now();
#endif
            // record new children into corpus
            campaign->corpus->FlushGeneration();
#ifdef REG_PROFILE
            campaign->econo_dur += (std::chrono::steady_clock::now() - econo_start);
#endif

            campaign->num_generations++;
            
            campaign->work_queue->Fill(campaign->corpus);
        }

        CorpusEntry<Char> *parent = campaign->work_queue->Pop();

        // Create children
#ifdef REG_PROFILE
        std::chrono::steady_clock::time_point gen_start = std::chrono::steady_clock::now();
#endif
        children_to_eval.clear();
        campaign->corpus->GenerateChildren(
            parent->buf,
            parent->buflen,
            N_CHILDREN_PER_PARENT,
            children_to_eval
        );
#ifdef REG_PROFILE
        campaign->gen_child_dur += (std::chrono::steady_clock::now() - gen_start);
#endif

        // Evaluate each child
        for (size_t j = 0; j < children_to_eval.size(); j++)
        {
            Char *child = children_to_eval[j];
            evaluate_child<Char>(
                context,
                child,
                strlen,
                regexp,
                campaign,
                parent
            );
        }
    }
}


uint64_t Fuzz(
    v8::Isolate *isolate,
    regulator::executor::V8RegExp *regexp,
    size_t strlen,
    bool fuzz_one_byte,
    bool fuzz_two_byte)
{
    exec_context context;

    // Set up context (used at work-interrupt points)
    context.begin = std::chrono::steady_clock::now();
    context.deadline = context.begin + std::chrono::seconds(regulator::flags::FLAG_timeout);
    context.exit_requested = false;
    context.last_screen_render = context.begin - std::chrono::hours(10000);

    if (fuzz_one_byte)
    {
        context.campaign_one_byte = new FuzzCampaign<uint8_t>();

        if (!seed_corpus(context.campaign_one_byte->corpus, regexp, strlen))
        {
            return 0;
        }

        std::vector<uint8_t> *interesting = new std::vector<uint8_t>();
        if (!fuzz::ExtractInteresting(*regexp, *interesting))
        {
            return 0;
        }
        context.campaign_one_byte->corpus->SetInteresting(interesting);
    }
    else
    {
        context.campaign_one_byte = nullptr;
    }

    if (fuzz_two_byte)
    {
        context.campaign_two_byte = new FuzzCampaign<uint16_t>();
        
        if (!seed_corpus(context.campaign_two_byte->corpus, regexp, strlen))
        {
            return 0;
        }

        std::vector<uint16_t> *interesting = new std::vector<uint16_t>();
        if (!fuzz::ExtractInteresting(*regexp, *interesting))
        {
            return 0;
        }
        context.campaign_two_byte->corpus->SetInteresting(interesting);
    }
    else
    {
        context.campaign_two_byte = nullptr;
    }


    if (f::FLAG_debug)
    {
        std::cout << "DEBUG Baseline established. Proceeding to main work loop." << std::endl;
    }

    // how long we can work on each corpus
    constexpr auto work_period = std::chrono::milliseconds(100);

    while (!context.exit_requested)
    {
        if (fuzz_one_byte)
        {
            context.campaign_one_byte->yield_deadline = std::chrono::steady_clock::now() + work_period;
            work_on_corpus(
                context,
                regexp,
                strlen,
                context.campaign_one_byte
            );
            work_interrupt(context);
        }

        if (fuzz_two_byte)
        {
            context.campaign_two_byte->yield_deadline = std::chrono::steady_clock::now() + work_period;
            work_on_corpus(
                context,
                regexp,
                strlen,
                context.campaign_two_byte
            );
            work_interrupt(context);
        }
    }

    return 1;
}

}

}
