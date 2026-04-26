// Copyright (C) 2026 Roman Lyubimov
// SPDX-License-Identifier: GPL-3.0-or-later

#include "util.h"

#include <cassert>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <set>
#include <vector>

#define EXPECT(cond) do {                                                  \
    if (!(cond)) {                                                          \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__                 \
                  << " " #cond "\n";                                        \
        std::exit(1);                                                       \
    }                                                                       \
} while (0)

namespace {

void test_ttl_for_size() {
    using util::ttlForSize;
    constexpr std::int64_t MAX_BYTES = 100LL * 1024 * 1024;   // 100 MB
    constexpr std::int64_t MIN_TTL   = 3600;                  // 1 h
    constexpr std::int64_t MAX_TTL   = 30LL * 24 * 3600;      // 30 d

    // Sub-kilobyte sizes all sit at the flat top.
    EXPECT(ttlForSize(0,    MAX_BYTES, MIN_TTL, MAX_TTL) == MAX_TTL);
    EXPECT(ttlForSize(1,    MAX_BYTES, MIN_TTL, MAX_TTL) == MAX_TTL);
    EXPECT(ttlForSize(1023, MAX_BYTES, MIN_TTL, MAX_TTL) == MAX_TTL);
    EXPECT(ttlForSize(1024, MAX_BYTES, MIN_TTL, MAX_TTL) == MAX_TTL);

    // One byte over the floor → strictly less than max (slope kicks in).
    EXPECT(ttlForSize(1025, MAX_BYTES, MIN_TTL, MAX_TTL) < MAX_TTL);

    // Exactly max_paste_bytes → min_ttl.
    EXPECT(ttlForSize(MAX_BYTES, MAX_BYTES, MIN_TTL, MAX_TTL) == MIN_TTL);

    // Over the cap clamps to min_ttl, never below.
    EXPECT(ttlForSize(MAX_BYTES * 10, MAX_BYTES, MIN_TTL, MAX_TTL) == MIN_TTL);

    // Negative clamps to max_ttl.
    EXPECT(ttlForSize(-5, MAX_BYTES, MIN_TTL, MAX_TTL) == MAX_TTL);

    // Monotone non-increasing past the floor.
    auto a = ttlForSize(2 * 1024,           MAX_BYTES, MIN_TTL, MAX_TTL);
    auto b = ttlForSize(1024 * 1024,        MAX_BYTES, MIN_TTL, MAX_TTL);
    auto c = ttlForSize(50LL * 1024 * 1024, MAX_BYTES, MIN_TTL, MAX_TTL);
    EXPECT(a >= b);
    EXPECT(b >= c);

    // Exponential decay (k=5) anchored to (0, MAX_TTL) and (1, MIN_TTL):
    //   frac(0.5) = (e^-2.5 - e^-5) / (1 - e^-5) ≈ 0.0759
    // For MAX_BYTES/2 the ratio sits within rounding distance of 0.5, so
    // expect ~MIN_TTL + 0.0759 * (MAX_TTL - MIN_TTL) ≈ 200k s. ±5 % window.
    const auto mid = ttlForSize(MAX_BYTES / 2, MAX_BYTES, MIN_TTL, MAX_TTL);
    const double expectedFrac = (std::exp(-2.5) - std::exp(-5.0))
                              / (1.0 - std::exp(-5.0));
    const auto expectedMid = static_cast<std::int64_t>(
        MIN_TTL + (MAX_TTL - MIN_TTL) * expectedFrac);
    EXPECT(std::llabs(mid - expectedMid) <= expectedMid / 20);

    // Degenerate config — min == max collapses to a constant.
    EXPECT(ttlForSize(0,    MAX_BYTES, 1234, 1234) == 1234);
    EXPECT(ttlForSize(9999, MAX_BYTES, 1234, 1234) == 1234);
}

void test_base64_round_trip() {
    using util::base64Encode;
    using util::base64Decode;

    auto roundTrip = [](std::vector<std::uint8_t> v) {
        bool ok = false;
        auto dec = base64Decode(base64Encode(v), &ok);
        EXPECT(ok);
        EXPECT(dec == v);
    };
    roundTrip({});
    roundTrip({0});
    roundTrip({0xff});
    roundTrip({1, 2, 3});
    roundTrip({1, 2, 3, 4});
    roundTrip({0, 1, 2, 3, 4, 5, 250, 255, 128});

    // 256-byte payload exercises every byte value.
    std::vector<std::uint8_t> all(256);
    for (int i = 0; i < 256; ++i) all[i] = static_cast<std::uint8_t>(i);
    roundTrip(all);

    // Padding shape.
    EXPECT(base64Encode(std::vector<std::uint8_t>{1}).back()      == '=');
    EXPECT(base64Encode(std::vector<std::uint8_t>{1, 2}).back()   == '=');
    EXPECT(base64Encode(std::vector<std::uint8_t>{1, 2, 3}).back() != '=');

    // Whitespace tolerated in decode (used when long base64 is line-wrapped).
    std::string wrapped = "AQID\nBA==";
    bool ok = false;
    auto dec = base64Decode(wrapped, &ok);
    EXPECT(ok);
    EXPECT((dec == std::vector<std::uint8_t>{1, 2, 3, 4}));

    // Garbage character returns ok=false.
    bool ok2 = true;
    base64Decode("###", &ok2);
    EXPECT(!ok2);
}

void test_paste_id() {
    // 1000 ids: every one is exactly 8 chars from [A-Za-z0-9]. We do not
    // assert uniqueness (two collisions in 62^8 over 1000 draws would still
    // be astronomically unlikely; the loop just exercises the alphabet).
    std::set<std::string> seen;
    for (int i = 0; i < 1000; ++i) {
        const auto id = util::randomPasteId();
        EXPECT(id.size() == 8);
        for (char c : id) EXPECT(std::isalnum(static_cast<unsigned char>(c)));
        seen.insert(id);
    }
    EXPECT(seen.size() > 990);   // collisions in a 1000-draw window are virtually impossible.
}

void test_random_token_hex() {
    const auto t = util::randomTokenHex();
    EXPECT(t.size() == 32);
    for (char c : t) {
        EXPECT((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
    EXPECT(t != util::randomTokenHex());
}

void test_random_bytes() {
    EXPECT(util::randomBytes(0).empty());
    const auto a = util::randomBytes(32);
    const auto b = util::randomBytes(32);
    EXPECT(a.size() == 32);
    EXPECT(b.size() == 32);
    EXPECT(a != b);   // 1 in 2^256 of failing — accept the math.
}

void test_ct_equal() {
    using util::ctEqual;
    EXPECT(ctEqual({1, 2, 3}, {1, 2, 3}));
    EXPECT(!ctEqual({1, 2, 3}, {1, 2, 4}));
    EXPECT(!ctEqual({1, 2}, {1, 2, 3}));
    EXPECT(ctEqual({}, {}));
}

}  // namespace

int main() {
    test_ttl_for_size();
    test_base64_round_trip();
    test_paste_id();
    test_random_token_hex();
    test_random_bytes();
    test_ct_equal();
    std::cout << "test_util OK\n";
    return 0;
}
