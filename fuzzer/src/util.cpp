#include <vector>
#include "util.hpp"

namespace regulator
{
    bool base64_decode(const std::string &in, uint8_t *&out, size_t &outlen) {
        // adapted from https://stackoverflow.com/a/13935718
        std::vector<uint8_t> vout;

        std::vector<int> T(256,-1);
        for (int i=0; i<64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i; 

        int val=0, valb=-8;
        for (uint8_t c : in) {
            if (T[c] == -1) break;
            val = (val<<6) + T[c];
            valb += 6;
            if (valb>=0) {
                vout.push_back(char((val>>valb)&0xFF));
                valb-=8;
            }
        }

        out = new uint8_t[vout.size() + 1];
        for (size_t i=0; i < vout.size(); i++)
        {
            out[i] = vout[i];
        }

        out[vout.size()] = 0;

        outlen = vout.size();

        return true;
    }

    bool base64_decode(const std::string &in, uint16_t *&out, size_t &outlen)
    {
        // UNTESTED
        uint8_t *tmp;
        size_t tmplen;
        base64_decode(in, tmp, outlen);
        if (outlen % 2 != 0)
        {
            // cannot use odd-length data
            delete[] tmp;
            out = nullptr;
            outlen = SIZE_MAX;
            return false;
        }
        out = reinterpret_cast<uint16_t *>(tmp);
        outlen = tmplen / 2;
        for (size_t i=0; i < outlen; i++)
        {
            out[i] = le16toh(out[i]);
        }
        return true;
    }
}