#include <string>
#include <cstdint>

namespace regulator
{
    bool base64_decode_one_byte(const std::string &in, uint8_t *&out, size_t &outlen);
    bool base64_decode_two_byte(const std::string &in, uint16_t *&out, size_t &outlen);
}
