// Copyright (C) 2026 Roman Lyubimov
// SPDX-License-Identifier: GPL-3.0-or-later

#include "util.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <mutex>
#include <random>

namespace util {

namespace {

std::mt19937_64& rng() {
    static std::mt19937_64 instance{std::random_device{}()};
    return instance;
}
std::mutex& rngMutex() {
    static std::mutex m;
    return m;
}

constexpr char kPasteAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";  // 62
constexpr char kHex[] = "0123456789abcdef";
constexpr char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

}  // namespace

std::string randomPasteId() {
    std::string s(8, '0');
    std::lock_guard<std::mutex> lk(rngMutex());
    auto& r = rng();
    for (int i = 0; i < 8; ++i) {
        s[i] = kPasteAlphabet[r() % 62];
    }
    return s;
}

std::vector<std::uint8_t> randomBytes(std::size_t n) {
    std::vector<std::uint8_t> out(n);
    std::lock_guard<std::mutex> lk(rngMutex());
    auto& r = rng();
    for (std::size_t i = 0; i < n; i += 8) {
        std::uint64_t v = r();
        for (std::size_t j = 0; j < 8 && i + j < n; ++j) {
            out[i + j] = static_cast<std::uint8_t>((v >> (j * 8)) & 0xFFu);
        }
    }
    return out;
}

std::string randomTokenHex() {
    const auto bytes = randomBytes(16);
    std::string s(32, '0');
    for (std::size_t i = 0; i < 16; ++i) {
        s[2 * i]     = kHex[bytes[i] >> 4];
        s[2 * i + 1] = kHex[bytes[i] & 0x0F];
    }
    return s;
}

std::string base64Encode(const std::uint8_t* bytes, std::size_t n) {
    std::string out;
    out.reserve(((n + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        std::uint32_t v = (std::uint32_t(bytes[i])     << 16)
                        | (std::uint32_t(bytes[i + 1]) << 8)
                        |  std::uint32_t(bytes[i + 2]);
        out.push_back(kB64[(v >> 18) & 0x3F]);
        out.push_back(kB64[(v >> 12) & 0x3F]);
        out.push_back(kB64[(v >> 6)  & 0x3F]);
        out.push_back(kB64[ v        & 0x3F]);
    }
    if (i < n) {
        std::uint32_t v = std::uint32_t(bytes[i]) << 16;
        const bool two = (i + 1 < n);
        if (two) {
            v |= std::uint32_t(bytes[i + 1]) << 8;
        }
        out.push_back(kB64[(v >> 18) & 0x3F]);
        out.push_back(kB64[(v >> 12) & 0x3F]);
        out.push_back(two ? kB64[(v >> 6) & 0x3F] : '=');
        out.push_back('=');
    }
    return out;
}

std::string base64Encode(const std::vector<std::uint8_t>& bytes) {
    return base64Encode(bytes.data(), bytes.size());
}

std::vector<std::uint8_t> base64Decode(const std::string& s, bool* ok) {
    static int8_t table[256];
    static bool inited = [] {
        for (auto& x : table) {
            x = -1;
        }
        for (int i = 0; i < 64; ++i) {
            table[static_cast<unsigned char>(kB64[i])] = static_cast<int8_t>(i);
        }
        return true;
    }();
    (void)inited;

    std::vector<std::uint8_t> out;
    out.reserve(s.size() * 3 / 4);
    std::uint32_t buf = 0;
    int bits = 0;
    for (char c : s) {
        if (c == '=') {
            break;
        }
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
            continue;
        }
        const int8_t v = table[static_cast<unsigned char>(c)];
        if (v < 0) {
            if (ok) {
                *ok = false;
            }
            return {};
        }
        buf = (buf << 6) | std::uint32_t(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((buf >> bits) & 0xFFu));
        }
    }
    if (ok) {
        *ok = true;
    }
    return out;
}

bool ctEqual(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

std::int64_t nowSeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t ttlForSize(std::int64_t size,
                        std::int64_t maxBytes,
                        std::int64_t minTtl,
                        std::int64_t maxTtl) {
    // Sub-kilobyte pastes are pinned to maxTtl: envelope/header overhead
    // alone pushes the size into double digits, so there is no meaningful
    // "smallness" granularity to reward below 1 KiB.
    constexpr std::int64_t kFloor = 1024;

    if (maxBytes <= kFloor) {
        return maxTtl;
    }
    if (size <= kFloor) {
        return maxTtl;
    }
    if (size > maxBytes) {
        size = maxBytes;
    }

    // Exponential decay anchored exactly to (0, maxTtl) and (1, minTtl):
    //   ttl = minTtl + (maxTtl - minTtl) * (exp(-k*r) - exp(-k)) / (1 - exp(-k))
    // where r = (size - kFloor) / (maxBytes - kFloor) ∈ [0, 1] and k controls
    // how aggressively the curve drops. Higher k → flat top for small files
    // and a sharp cliff near the cap. k=5 keeps small/medium pastes near the
    // ceiling while pushing the largest ones quickly down to minTtl.
    constexpr double kDecay = 5.0;
    const double ratio = static_cast<double>(size - kFloor)
                       / static_cast<double>(maxBytes - kFloor);
    const double e_kr  = std::exp(-kDecay * ratio);
    const double e_k   = std::exp(-kDecay);
    const double frac  = (e_kr - e_k) / (1.0 - e_k);
    const double span  = static_cast<double>(maxTtl - minTtl);
    const auto ttl = static_cast<std::int64_t>(static_cast<double>(minTtl) + span * frac);
    return std::max<std::int64_t>(minTtl, std::min<std::int64_t>(maxTtl, ttl));
}

}  // namespace util
