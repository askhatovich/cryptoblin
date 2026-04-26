// Copyright (C) 2026 Roman Lyubimov
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <string>

class Config {
public:
    static Config& instance();

    bool loadFromFile(const std::string& path);

    // [server]
    std::string logLevel    = "info";
    std::string bindAddress = "0.0.0.0";
    uint16_t    bindPort    = 8080;
    std::string appName     = "CryptoBlin";
    std::string title       = "";   // shown in <title> + header; falls back to appName

    // [storage]
    std::string dbPath  = "/var/lib/cryptoblin/cryptoblin.sqlite";
    std::string blobDir = "/var/lib/cryptoblin/blobs";

    // [retention] — TTL is computed linearly from size:
    //   ttl = maxTtl - (maxTtl - minTtl) * (size / maxPasteBytes)
    // so a 1-byte paste lives ~maxTtl seconds and a maxPasteBytes paste
    // lives exactly minTtl seconds.
    int64_t maxPasteBytes = 100LL * 1024 * 1024;   // 100 MB
    int64_t minTtlSeconds = 3600;                  // 1 hour
    int64_t maxTtlSeconds = 30LL * 24 * 3600;      // 30 days

    // [limits]
    int rateLimitPerIpSeconds = 3;
    int64_t totalPastesCap    = 0;                 // 0 = unlimited

    // [captcha]
    int powDifficultyBits  = 18;
    int powTtlSeconds      = 300;
};
