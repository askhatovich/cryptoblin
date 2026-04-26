// Copyright (C) 2026 Roman Lyubimov
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace util {

// 8-char alphanumeric (A-Za-z0-9, 62^8 ≈ 2.18e14) paste id.
std::string randomPasteId();

// 32 random hex chars — used for opaque session tokens (16 bytes).
std::string randomTokenHex();

// n random bytes.
std::vector<std::uint8_t> randomBytes(std::size_t n);

// Standard base64 encode/decode (with padding).
std::string base64Encode(const std::uint8_t* data, std::size_t n);
std::string base64Encode(const std::vector<std::uint8_t>& bytes);
std::vector<std::uint8_t> base64Decode(const std::string& s, bool* ok = nullptr);

// Constant-time vector compare.
bool ctEqual(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b);

// Current epoch seconds.
std::int64_t nowSeconds();

// TTL formula: linear in size, so larger pastes live shorter. The slope
// has a flat top — anything ≤ 1 KiB returns `maxTtl` exactly; only pastes
// bigger than that lose lifetime as they grow towards `maxBytes`.
std::int64_t ttlForSize(std::int64_t size,
                        std::int64_t maxBytes,
                        std::int64_t minTtl,
                        std::int64_t maxTtl);

}  // namespace util
