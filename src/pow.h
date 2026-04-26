// Copyright (C) 2026 Roman Lyubimov
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Stateless proof-of-work captcha for paste creation.
//
// On-the-wire token format (single ASCII string, no padding-sensitive bits):
//
//   <id_b64>.<expires_unix>.<difficulty>.<sig_b64>
//
//   id          : 16 random bytes, base64-encoded; replay-protection key
//   expires     : unix seconds when this token stops being accepted
//   difficulty  : required leading zero bits of SHA-256(token || ":" || nonce)
//   sig         : HMAC-SHA256(secret, "<id>.<expires>.<difficulty>"), base64
//
// The server only needs an in-memory secret + a replay set keyed by id.
// Restarting the daemon invalidates all outstanding tokens (signature key
// changes), which is acceptable because the TTL is short — clients just
// re-fetch `/api/captcha`.

#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace captcha {

struct Challenge {
    std::string  token;          // exact ASCII string sent to the client
    std::int64_t expiresUnix;
    unsigned     difficultyBits;
};

enum class VerifyResult {
    Ok,
    Malformed,
    BadSignature,
    Expired,
    InsufficientWork,
    Replay,
};

class ChallengeIssuer {
public:
    // `hmacSecret` must be at least 16 bytes — wrong-secret rejection is
    // total but we still want enough entropy that the secret isn't bruteable
    // out of band. Caller seeds it from the OS RNG at startup.
    ChallengeIssuer(std::string hmacSecret,
                    unsigned difficultyBits,
                    std::chrono::seconds ttl);

    Challenge issue();

    // Verifies signature, expiry, and proof-of-work, then atomically marks
    // the embedded id as consumed (so a token cannot be reused). On any
    // failure the replay set is left untouched so a slow legitimate client
    // can retry with the same token until expiry.
    VerifyResult verifyAndConsume(const std::string& token, const std::string& nonce);

    // Drop replay entries past their expiry. Call from the purger thread.
    void gcReplay();

private:
    std::string secret_;
    unsigned    difficultyBits_;
    std::chrono::seconds ttl_;

    std::mutex                                  replayMu_;
    std::unordered_map<std::string, std::int64_t> replay_;   // id -> expires_unix
};

}  // namespace captcha
