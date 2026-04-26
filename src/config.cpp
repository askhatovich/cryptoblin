// Copyright (C) 2026 Roman Lyubimov
// SPDX-License-Identifier: GPL-3.0-or-later

#include "config.h"
#include "config/inireader.h"

#include <iostream>

Config& Config::instance() {
    static Config c;
    return c;
}

bool Config::loadFromFile(const std::string& path) {
    INIReader r(path);
    if (r.ParseError() < 0) {
        std::cerr << "Failed to load config: " << path << std::endl;
        return false;
    }
    logLevel    = r.Get("server", "log_level",    logLevel);
    bindAddress = r.Get("server", "bind_address", bindAddress);
    bindPort    = static_cast<uint16_t>(r.GetInteger("server", "bind_port", bindPort));
    appName     = r.Get("server", "app_name",     appName);
    title       = r.Get("server", "title",        title);

    dbPath  = r.Get("storage", "db_path",  dbPath);
    blobDir = r.Get("storage", "blob_dir", blobDir);

    maxPasteBytes = r.GetInteger("retention", "max_paste_bytes", maxPasteBytes);
    minTtlSeconds = r.GetInteger("retention", "min_ttl_seconds", minTtlSeconds);
    maxTtlSeconds = r.GetInteger("retention", "max_ttl_seconds", maxTtlSeconds);

    rateLimitPerIpSeconds = static_cast<int>(r.GetInteger("limits", "rate_limit_per_ip_seconds", rateLimitPerIpSeconds));
    totalPastesCap        = r.GetInteger("limits", "total_pastes_cap", totalPastesCap);

    powDifficultyBits = static_cast<int>(r.GetInteger("captcha", "difficulty_bits", powDifficultyBits));
    powTtlSeconds     = static_cast<int>(r.GetInteger("captcha", "ttl_seconds",     powTtlSeconds));
    if (powDifficultyBits < 0) {
        powDifficultyBits = 0;
    }
    if (powDifficultyBits > 32) {
        powDifficultyBits = 32;
    }
    if (powTtlSeconds < 30) {
        powTtlSeconds = 30;
    }

    if (minTtlSeconds < 1) {
        minTtlSeconds = 1;
    }
    if (maxTtlSeconds < minTtlSeconds) {
        maxTtlSeconds = minTtlSeconds;
    }
    if (maxPasteBytes < 1) {
        maxPasteBytes = 1;
    }
    if (rateLimitPerIpSeconds < 0) {
        rateLimitPerIpSeconds = 0;
    }

    return true;
}
