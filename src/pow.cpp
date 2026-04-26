// Copyright (C) 2026 Roman Lyubimov
// SPDX-License-Identifier: GPL-3.0-or-later

#include "pow.h"

#include "sha256/sha256.h"
#include "util.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace captcha {

namespace {

constexpr std::size_t kSha256BlockBytes = 64;
constexpr std::size_t kSha256DigestBytes = 32;
constexpr std::size_t kIdBytes = 16;
constexpr std::size_t kReplayCap = 100'000;

std::array<std::uint8_t, kSha256DigestBytes> sha256Bytes(const std::uint8_t* data, std::size_t n) {
    tools::SHA256 h;
    h.update(data, n);
    return h.digest();
}

// HMAC-SHA256(key, msg). Built on top of the vendored tools::SHA256 — keeps
// the daemon free of an OpenSSL dependency. The construction is straight
// FIPS 198-1.
std::array<std::uint8_t, kSha256DigestBytes>
hmacSha256(const std::string& key, const std::string& msg) {
    std::array<std::uint8_t, kSha256BlockBytes> kpad{};
    if (key.size() > kSha256BlockBytes) {
        const auto kh = sha256Bytes(reinterpret_cast<const std::uint8_t*>(key.data()), key.size());
        std::memcpy(kpad.data(), kh.data(), kh.size());
    } else {
        std::memcpy(kpad.data(), key.data(), key.size());
    }

    std::array<std::uint8_t, kSha256BlockBytes> ipad{}, opad{};
    for (std::size_t i = 0; i < kSha256BlockBytes; ++i) {
        ipad[i] = kpad[i] ^ 0x36;
        opad[i] = kpad[i] ^ 0x5C;
    }

    tools::SHA256 inner;
    inner.update(ipad.data(), ipad.size());
    inner.update(reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size());
    const auto innerDigest = inner.digest();

    tools::SHA256 outer;
    outer.update(opad.data(), opad.size());
    outer.update(innerDigest.data(), innerDigest.size());
    return outer.digest();
}

unsigned leadingZeroBits(const std::array<std::uint8_t, kSha256DigestBytes>& d) {
    unsigned count = 0;
    for (auto b : d) {
        if (b == 0) {
            count += 8;
            continue;
        }
        for (int i = 7; i >= 0; --i) {
            if ((b >> i) & 1) {
                return count;
            }
            ++count;
        }
        return count;
    }
    return count;
}

bool parseI64(const std::string& s, std::int64_t* out) {
    if (s.empty()) {
        return false;
    }
    std::int64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
        v = v * 10 + (c - '0');
    }
    *out = v;
    return true;
}

bool parseUint(const std::string& s, unsigned* out) {
    if (s.empty()) {
        return false;
    }
    unsigned v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
        v = v * 10 + static_cast<unsigned>(c - '0');
    }
    *out = v;
    return true;
}

bool ctEqualBytes(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    unsigned char d = 0;
    for (std::size_t i = 0; i < n; ++i) {
        d |= a[i] ^ b[i];
    }
    return d == 0;
}

std::string nowSecs() {
    return std::to_string(util::nowSeconds());
}

}  // namespace

ChallengeIssuer::ChallengeIssuer(std::string secret,
                                 unsigned difficultyBits,
                                 std::chrono::seconds ttl)
    : secret_(std::move(secret)), difficultyBits_(difficultyBits), ttl_(ttl) {}

Challenge ChallengeIssuer::issue() {
    Challenge c;
    c.expiresUnix    = util::nowSeconds() + ttl_.count();
    c.difficultyBits = difficultyBits_;

    const auto idBytes = util::randomBytes(kIdBytes);
    const std::string idB64 = util::base64Encode(idBytes);

    std::string payload = idB64;
    payload.push_back('.');
    payload.append(std::to_string(c.expiresUnix));
    payload.push_back('.');
    payload.append(std::to_string(c.difficultyBits));

    const auto sig = hmacSha256(secret_, payload);
    const std::string sigB64 = util::base64Encode(sig.data(), sig.size());

    c.token = payload + "." + sigB64;
    return c;
}

VerifyResult ChallengeIssuer::verifyAndConsume(const std::string& token, const std::string& nonce) {
    // Split into 4 fields by '.'. We need the first three again as the
    // signed payload, so keep both the parts and an index of dots.
    std::array<std::string, 4> parts;
    std::size_t partIdx = 0;
    std::size_t lastDot = std::string::npos;
    for (std::size_t i = 0; i < token.size(); ++i) {
        if (token[i] == '.') {
            if (partIdx >= 3) return VerifyResult::Malformed;
            parts[partIdx++] = token.substr(lastDot == std::string::npos ? 0 : lastDot + 1,
                                             i - (lastDot == std::string::npos ? 0 : lastDot + 1));
            lastDot = i;
        }
    }
    if (partIdx != 3) return VerifyResult::Malformed;
    parts[3] = token.substr(lastDot + 1);

    std::int64_t expires = 0;
    unsigned     difficulty = 0;
    if (!parseI64(parts[1], &expires))     return VerifyResult::Malformed;
    if (!parseUint(parts[2], &difficulty)) return VerifyResult::Malformed;

    bool ok = false;
    const auto idBytes = util::base64Decode(parts[0], &ok);
    if (!ok || idBytes.size() != kIdBytes) return VerifyResult::Malformed;
    const auto sigBytes = util::base64Decode(parts[3], &ok);
    if (!ok || sigBytes.size() != kSha256DigestBytes) return VerifyResult::Malformed;

    const std::string payload = parts[0] + "." + parts[1] + "." + parts[2];
    const auto expected = hmacSha256(secret_, payload);
    if (!ctEqualBytes(expected.data(), sigBytes.data(), kSha256DigestBytes)) {
        return VerifyResult::BadSignature;
    }

    if (util::nowSeconds() > expires) return VerifyResult::Expired;

    // Proof of work: SHA-256(token || ":" || nonce) must clear `difficulty`
    // leading zero bits.
    {
        tools::SHA256 h;
        h.update(reinterpret_cast<const std::uint8_t*>(token.data()), token.size());
        const std::uint8_t colon = ':';
        h.update(&colon, 1);
        h.update(reinterpret_cast<const std::uint8_t*>(nonce.data()), nonce.size());
        const auto digest = h.digest();
        if (leadingZeroBits(digest) < difficulty) return VerifyResult::InsufficientWork;
    }

    // Replay check is the last gate so a malformed/wrong-PoW request never
    // pollutes the replay set with attacker-controlled ids.
    const std::string idKey(reinterpret_cast<const char*>(idBytes.data()), idBytes.size());
    {
        std::lock_guard<std::mutex> lk(replayMu_);
        if (replay_.find(idKey) != replay_.end()) return VerifyResult::Replay;
        if (replay_.size() >= kReplayCap) {
            // Drop arbitrary entries to bound memory under abuse. Legit
            // clients still re-fetch and retry.
            replay_.erase(replay_.begin());
        }
        replay_.emplace(idKey, expires);
    }
    return VerifyResult::Ok;
}

void ChallengeIssuer::gcReplay() {
    const auto now = util::nowSeconds();
    std::lock_guard<std::mutex> lk(replayMu_);
    for (auto it = replay_.begin(); it != replay_.end();) {
        if (it->second <= now) it = replay_.erase(it);
        else                   ++it;
    }
}

}  // namespace captcha
