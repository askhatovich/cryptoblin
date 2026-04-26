#pragma once

#include <string>

namespace blin {

// Find a decimal nonce (as a string) such that
//   leading_zero_bits(SHA-256(token + ":" + nonce)) >= difficulty.
std::string solvePow(const std::string& token, unsigned difficulty);

}  // namespace blin
