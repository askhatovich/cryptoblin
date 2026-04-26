// Copyright (C) 2026 Roman Lyubimov
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "crowlib/crow/app.h"
#include "pow.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class Database;

class WebAPI {
public:
    explicit WebAPI(Database& db);

    void run();
    void stop();

    // Periodic housekeeping called by the purger thread.
    void gcRateLimiter();
    void gcSessions();
    void gcPow();

private:
    void initRoutes();

    bool rateLimitAdmit(const std::string& ip);

    // One open-paste handshake. The token is allocated by /open and consumed
    // by /blob. For non-existent pastes the handshake still succeeds at the
    // /open step (decoy) but `realId` is empty so /blob always rejects with
    // the same error code as a wrong-key attempt — an enumeration attacker
    // cannot tell the two cases apart.
    struct ChallengeSession {
        std::string realId;                              // empty -> decoy
        std::vector<std::uint8_t> expectedPlaintext;     // 32 bytes
        std::chrono::steady_clock::time_point expiresAt;
    };

    Database&       db_;
    crow::SimpleApp app_;
    std::string     bundleEtag_;
    std::string     bundleHtml_;
    std::unique_ptr<captcha::ChallengeIssuer> pow_;

    std::mutex                                                                 rateLimitMu_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point>     lastSeen_;

    std::mutex                                       sessionsMu_;
    std::unordered_map<std::string, ChallengeSession> sessions_;
};
