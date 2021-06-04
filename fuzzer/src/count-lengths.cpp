#include <iostream>
#include "count-lengths.hpp"
#include "util.hpp"

using namespace std;
using namespace regulator::executor;

#if defined REG_COUNT_PATHLENGTH

void regulator::loop_count_lengths(regulator::ParsedArguments &args, regulator::executor::V8RegExp &regexp, int width)
{
    args.count_paths;
    V8RegExpResult result;
    for (std::string line; std::getline(std::cin, line);)
    {
        if (width == 1)
        {
            uint8_t *buf;
            size_t buflen;
            if (!regulator::base64_decode_one_byte(line, buf, buflen))
            {
                std::cout << "DECODE_FAIL" << std::endl;
                continue;
            }

            result.coverage_tracker->Clear();
            Result status = Exec(
                &regexp,
                buf,
                buflen,
                result,
                -1,
                args.max_path,
                kOnlyOneByte
            );
            std::cout << "TOTCOUNT " << result.coverage_tracker->PathLength() << std::endl;
            delete[] buf;
        }
        else
        {
            uint16_t *buf;
            size_t buflen;
            if (!regulator::base64_decode_two_byte(line, buf, buflen))
            {
                std::cout << "DECODE_FAIL" << std::endl;
                continue;
            }

            result.coverage_tracker->Clear();
            Result status = Exec(
                &regexp,
                buf,
                buflen,
                result,
                -1,
                args.max_path,
                kOnlyTwoByte
            );
            std::cout << "TOTCOUNT " << result.coverage_tracker->PathLength() << std::endl;
            delete[] buf;
        }
    }
}
#endif
