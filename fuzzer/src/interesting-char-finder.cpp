#include "interesting-char-finder.hpp"
#include "regexp-executor.hpp"
#include "flags.hpp"

#include "src/regexp/regexp-bytecodes.h"
#include "src/objects/fixed-array.h"
#include "src/objects/fixed-array-inl.h"

#include <vector>
#include <memory>
#include <iomanip>

namespace e = regulator::executor;

namespace regulator
{
namespace fuzz
{

template<typename Char>
bool ExtractInteresting(
    e::V8RegExp &regexp,
    std::vector<Char> &out
)
{
    // ensure that the regexp is compiled for this Char width
    // by executing it once
    Char subject[4];
    subject[0] = sizeof(Char) == 1 ? '0' : 0x03b3; // either '0' or greek small letter gamma
    subject[1] = '1';
    subject[2] = '2';
    subject[3] = '3';

    e::V8RegExpResult exec_result;

    e::Result result = e::Exec(
        &regexp,
        subject,
        sizeof(subject) / sizeof(Char),
        exec_result,
        -1,
        sizeof(Char) == 1 ? e::kOnlyOneByte : e::kOnlyTwoByte
    );

    if (result != e::kSuccess)
    {
        std::cerr << "Failed to execute regexp for interesting char extraction!" << std::endl;
        return false;
    }

    v8::internal::ByteArray ba = v8::internal::ByteArray::cast(
        regexp.regexp->Bytecode(sizeof(Char) == 1)
    );

    // either 32 bytes or 8kb (yeah, explodes ...)
    constexpr size_t num_bytes_in_bitmap = ((1 << (sizeof(Char) * 8))) / 8;
    std::unique_ptr<uint8_t[]> bitmap(new uint8_t[num_bytes_in_bitmap]);
    memset(bitmap.get(), 0, num_bytes_in_bitmap);

    const uint8_t *code_start = ba.GetDataStartAddress();
    const uint8_t *code_end = ba.GetDataEndAddress();

    const uint8_t *pc = code_start;

    // Iterate over each instruction to see if there's anything interesting
    while (pc < code_end)
    {
#define SET_CHAR_BIT(__c) bitmap[static_cast<uint16_t>(__c) / 8] |= static_cast<uint16_t>(1 << (static_cast<uint16_t>(__c) % 8))
        int32_t instruction = *reinterpret_cast<const int32_t *>(pc);

        // NOTE: the 'negative' matches seen below are included because
        // they don't necessarily mean the "no-match" branch is failure, it
        // could just be another alternative

        switch (instruction & v8::internal::BYTECODE_MASK)
        {
        case v8::internal::BC_CHECK_4_CHARS:
        case v8::internal::BC_CHECK_NOT_4_CHARS:
            {
                // NOTE: this probably should only be used in 1-byte mode
                if (sizeof(Char) != 1)
                {
                    return false;
                }
                SET_CHAR_BIT(*(pc + 4));
                SET_CHAR_BIT(*(pc + 5));
                SET_CHAR_BIT(*(pc + 6));
                SET_CHAR_BIT(*(pc + 7));
            }
            break;
        case v8::internal::BC_CHECK_CHAR:
        case v8::internal::BC_CHECK_NOT_CHAR:
            {
                uint32_t c = instruction >> v8::internal::BYTECODE_SHIFT;
                if (sizeof(Char) == 1)
                {
                    c &= 0xff;
                    // bitmap[c / 8] = bitmap[c / 8] | static_cast<uint8_t>(1 << (static_cast<uint8_t>(c) % 8));
                    SET_CHAR_BIT(c & 0xff);
                    SET_CHAR_BIT((c >> 8 ) & 0xff);
                    SET_CHAR_BIT((c >> 16) & 0xff);
                }
                else
                {
                    SET_CHAR_BIT(c & 0xffff);
                }
            }
            break;
        case v8::internal::BC_AND_CHECK_4_CHARS:
        case v8::internal::BC_AND_CHECK_NOT_4_CHARS:
            {
                uint32_t pattern = *reinterpret_cast<const uint32_t *>(pc + 4);
                uint32_t mask = *reinterpret_cast<const uint32_t *>(pc + 8);
                if (sizeof(Char) != 1)
                {
                    return false;
                }
                SET_CHAR_BIT(pattern & 0xff);
                SET_CHAR_BIT((pattern >>  8) & 0xff);
                SET_CHAR_BIT((pattern >> 16) & 0xff);
                SET_CHAR_BIT((pattern >> 24) & 0xff);
                // notice that negating the mask gets the bits which are indifferent
                // so let's just negate and use 1's to get more interesting chars
                uint32_t neg_mask = ~mask;
                SET_CHAR_BIT((pattern | neg_mask) & 0xff);
                SET_CHAR_BIT(((pattern | neg_mask) >>  8) & 0xff);
                SET_CHAR_BIT(((pattern | neg_mask) >> 16) & 0xff);
                SET_CHAR_BIT(((pattern | neg_mask) >> 24) & 0xff);
            }
            break;
        case v8::internal::BC_AND_CHECK_CHAR:
        case v8::internal::BC_AND_CHECK_NOT_CHAR:
            {
                uint32_t c = instruction >> v8::internal::BYTECODE_SHIFT;
                uint32_t mask = *reinterpret_cast<const uint32_t *>(pc + 4);
                uint32_t neg_mask = ~mask;
                if (sizeof(Char) == 1)
                {
                    SET_CHAR_BIT(c & 0xff);
                    SET_CHAR_BIT((c >>  8) & 0xff);
                    SET_CHAR_BIT((c >> 16) & 0xff);
                    SET_CHAR_BIT((c >> 24) & 0xff);
                    SET_CHAR_BIT((c | neg_mask) & 0xff);
                    SET_CHAR_BIT(((c | neg_mask) >>  8) & 0xff);
                    SET_CHAR_BIT(((c | neg_mask) >> 16) & 0xff);
                    SET_CHAR_BIT(((c | neg_mask) >> 24) & 0xff);
                }
                else
                {
                    SET_CHAR_BIT(c & 0xffff);
                    SET_CHAR_BIT((c | neg_mask) & 0xffff);
                }
            }
            break;
        case v8::internal::BC_CHECK_CHAR_IN_RANGE:
        case v8::internal::BC_CHECK_CHAR_NOT_IN_RANGE:
            {
                uint32_t from = *reinterpret_cast<const uint16_t *>(pc + 4);
                uint32_t to   = *reinterpret_cast<const uint16_t *>(pc + 6);
                SET_CHAR_BIT(from);
                SET_CHAR_BIT(from - 1);
                SET_CHAR_BIT(to);
                SET_CHAR_BIT(to + 1);
            }
            break;
        case v8::internal::BC_CHECK_LT:
            {
                uint32_t c = instruction >> v8::internal::BYTECODE_SHIFT;
                SET_CHAR_BIT(c);
                SET_CHAR_BIT(c - 1);
            }
            break;
        case v8::internal::BC_CHECK_GT:
            {
                uint32_t c = instruction >> v8::internal::BYTECODE_SHIFT;
                SET_CHAR_BIT(c);
                SET_CHAR_BIT(c + 1);
            }
            break;
        case v8::internal::BC_SKIP_UNTIL_CHAR:
        case v8::internal::BC_SKIP_UNTIL_CHAR_POS_CHECKED:
            {
                uint32_t c = *reinterpret_cast<const uint16_t *>(pc + 6);
                SET_CHAR_BIT(c);
            }
            break;
        case v8::internal::BC_SKIP_UNTIL_CHAR_AND:
            {
                uint32_t c = *reinterpret_cast<const uint16_t *>(pc + 6);
                uint32_t mask = *reinterpret_cast<const uint32_t *>(pc + 8);
                uint32_t neg_mask = ~mask;
                if (sizeof(Char) == 1)
                {
                    SET_CHAR_BIT(c & 0xff);
                    SET_CHAR_BIT((c >>  8) & 0xff);
                    SET_CHAR_BIT((c >> 16) & 0xff);
                    SET_CHAR_BIT((c >> 24) & 0xff);
                    SET_CHAR_BIT((c | neg_mask) & 0xff);
                    SET_CHAR_BIT(((c | neg_mask) >>  8) & 0xff);
                    SET_CHAR_BIT(((c | neg_mask) >> 16) & 0xff);
                    SET_CHAR_BIT(((c | neg_mask) >> 24) & 0xff);
                }
                else
                {
                    SET_CHAR_BIT(c & 0xffff);
                    SET_CHAR_BIT((c | neg_mask) & 0xffff);
                }
            }
            break;
        case v8::internal::BC_SKIP_UNTIL_CHAR_OR_CHAR:
        case v8::internal::BC_SKIP_UNTIL_GT_OR_NOT_BIT_IN_TABLE:
        case v8::internal::BC_SKIP_UNTIL_BIT_IN_TABLE:
        case v8::internal::BC_CHECK_BIT_IN_TABLE:
        case v8::internal::BC_MINUS_AND_CHECK_NOT_CHAR:
        default:
            break;
        }

        pc += v8::internal::RegExpBytecodeLength(instruction & v8::internal::BYTECODE_MASK);
#undef SET_CHAR_BIT
    }

    // note: skip i=0 b/c we don't really care about null char
    for (size_t i=1; i<num_bytes_in_bitmap * 8; i++)
    {
        if ((bitmap[i / 8] & (1 << (i % 8))) != 0)
        {
            out.push_back(i & ((1 << (sizeof(Char) * 8)) - 1));
        }
    }

    if (regulator::flags::FLAG_debug)
    {
        std::cout << "DEBUG interesting chars (" << sizeof(Char) << "-byte): ";
        for (size_t i=0; i<out.size(); i++)
        {
            Char c = out[i];
            if (c == '\\')
            {
                std::cout << "\\\\";
            }
            else if ('!' <= c && c <= '~')
            {
                std::cout << static_cast<unsigned char>(c);
            }
            else
            {
                std::cout << "\\x" << std::hex << std::setw(sizeof(Char) * 2) << std::setfill('0')
                    << static_cast<uint16_t>(c)
                    << std::dec << std::setfill(' ');
            }
        }
        std::cout << std::endl;
    }

    return true;
}


template bool ExtractInteresting(e::V8RegExp &regexp, std::vector<uint8_t> &out);
template bool ExtractInteresting(e::V8RegExp &regexp, std::vector<uint16_t> &out);

} // namespace fuzz
} // namespace regulator
