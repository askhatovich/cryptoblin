#include "pow_solve.h"

#include "sha256/sha256.h"

#include <array>
#include <cstdint>
#include <string>

namespace blin {

namespace {

unsigned leadingZeroBits(const std::array<std::uint8_t, 32>& d) {
    unsigned n = 0;
    for (auto b : d) {
        if (b == 0) {
            n += 8;
            continue;
        }
        for (int i = 7; i >= 0; --i) {
            if ((b >> i) & 1) {
                return n;
            }
            ++n;
        }
        return n;
    }
    return n;
}

}  // namespace

std::string solvePow(const std::string& token, unsigned difficulty) {
    const std::string prefix = token + ":";
    for (std::uint64_t n = 0;; ++n) {
        const std::string nstr = std::to_string(n);
        tools::SHA256 h;
        h.update(reinterpret_cast<const std::uint8_t*>(prefix.data()), prefix.size());
        h.update(reinterpret_cast<const std::uint8_t*>(nstr.data()), nstr.size());
        const auto d = h.digest();
        if (leadingZeroBits(d) >= difficulty) {
            return nstr;
        }
    }
}

}  // namespace blin
