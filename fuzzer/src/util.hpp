#include <string>
#include <cstdint>

namespace regulator
{
    bool base64_decode(const std::string &in, uint8_t *&out, size_t &outlen);
    bool base64_decode(const std::string &in, uint16_t *&out, size_t &outlen);
}
