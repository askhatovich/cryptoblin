// Copyright (C) 2026 Roman Lyubimov
// SPDX-License-Identifier: GPL-3.0-or-later

#include "config.h"
#include "db.h"
#include "log.h"
#include "util.h"
#include "version.h"
#include "webapi.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

namespace fs = std::filesystem;

namespace {

constexpr const char* kDefaultConfigPath = "/etc/cryptoblin/config.ini";

constexpr const char* kDefaultConfigContent = R"INI([server]
log_level = info
bind_address = 0.0.0.0
bind_port = 8080
app_name = CryptoBlin

[storage]
db_path  = /var/lib/cryptoblin/cryptoblin.sqlite
blob_dir = /var/lib/cryptoblin/blobs

[retention]
; Hard upper bound on a single paste, in bytes.
max_paste_bytes = 104857600
; A 1-byte paste lives for max_ttl_seconds.
; A max_paste_bytes paste lives for min_ttl_seconds.
; Sizes between are linearly interpolated.
min_ttl_seconds = 3600
max_ttl_seconds = 2592000

[limits]
; Minimum interval (seconds) between captcha issuances from the same IP.
; Paste reads (/api/pastes/<id>/{open,blob}) are NOT rate-limited.
rate_limit_per_ip_seconds = 3
; 0 = no global cap on the number of pastes stored on this instance.
total_pastes_cap = 0

[captcha]
; Required leading zero bits in SHA-256(token + ":" + nonce). Each extra
; bit doubles the average work the browser must perform before it can
; submit a paste — 18 takes ~1-3 seconds in modern browsers.
difficulty_bits = 18
; How long an issued captcha stays valid for, in seconds.
ttl_seconds = 300
)INI";

void printHelp(const char* prog) {
    std::cout
        << "cryptoblin " << CRYPTOBLIN_VERSION << " (" << CRYPTOBLIN_GIT_SHORT << ")\n"
        << "Zero-knowledge pastebin server.\n\n"
        << "Usage:\n"
        << "  " << prog << " [options]\n\n"
        << "Options:\n"
        << "  -c, --config <path>            Path to config file (default: " << kDefaultConfigPath << ")\n"
        << "  -g, --generate-config <path>   Write a default config to <path> and exit\n"
        << "  -V, --version                  Print version and exit\n"
        << "  -h, --help                     Show this message\n";
}

plog::Severity parseLogLevel(const std::string& s) {
    std::string l = s;
    for (auto& c : l) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (l == "verbose") {
        return plog::verbose;
    }
    if (l == "debug") {
        return plog::debug;
    }
    if (l == "info") {
        return plog::info;
    }
    if (l == "warning") {
        return plog::warning;
    }
    if (l == "error") {
        return plog::error;
    }
    if (l == "fatal") {
        return plog::fatal;
    }
    if (l == "none") {
        return plog::none;
    }
    std::cerr << "Unknown log level '" << s << "', falling back to 'info'\n";
    return plog::info;
}

bool generateConfig(const std::string& path) {
    std::ofstream f(path);
    if (!f) {
        std::cerr << "Cannot write " << path << "\n";
        return false;
    }
    f << kDefaultConfigContent;
    return static_cast<bool>(f);
}

std::atomic<WebAPI*> g_api{nullptr};

extern "C" void onSignal(int) {
    if (auto* api = g_api.load()) {
        api->stop();
    }
}

void installSignalHandlers() {
    std::signal(SIGINT,  onSignal);
    std::signal(SIGTERM, onSignal);
}

}  // namespace

int main(int argc, char** argv) {
    std::string configPath = kDefaultConfigPath;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-h" || a == "--help") {
            printHelp(argv[0]);
            return 0;
        }
        if (a == "-V" || a == "--version") {
            std::cout << "cryptoblin " << CRYPTOBLIN_VERSION << " (" << CRYPTOBLIN_GIT_SHORT << ")\n";
            return 0;
        }
        if (a == "-g" || a == "--generate-config") {
            if (i + 1 >= argc) { std::cerr << "Missing path\n"; return 2; }
            return generateConfig(argv[++i]) ? 0 : 1;
        }
        if (a == "-c" || a == "--config") {
            if (i + 1 >= argc) { std::cerr << "Missing path\n"; return 2; }
            configPath = argv[++i];
            continue;
        }
        std::cerr << "Unknown argument: " << a << "\n";
        printHelp(argv[0]);
        return 2;
    }

    auto& cfg = Config::instance();
    if (!cfg.loadFromFile(configPath)) {
        std::cerr << "Run `" << argv[0] << " --generate-config <path>` to create a default config.\n";
        return 1;
    }

    static plog::ColorConsoleAppender<plog::TxtFormatter> consoleAppender;
    plog::init(parseLogLevel(cfg.logLevel), &consoleAppender);

    PLOGI << "cryptoblin " << CRYPTOBLIN_VERSION << " (" << CRYPTOBLIN_GIT_SHORT << ")";
    PLOGI << "binding " << cfg.bindAddress << ":" << cfg.bindPort
          << ", db=" << cfg.dbPath << ", blobs=" << cfg.blobDir;

    std::error_code ec;
    fs::create_directories(cfg.blobDir, ec);
    if (ec) {
        std::cerr << "Cannot create blob_dir " << cfg.blobDir << ": " << ec.message() << "\n";
        return 1;
    }

    std::unique_ptr<Database> db;
    try {
        db = Database::open(cfg.dbPath);
    } catch (const std::exception& e) {
        std::cerr << "Database error: " << e.what() << "\n";
        return 1;
    }

    WebAPI api(*db);
    g_api.store(&api);
    installSignalHandlers();

    // Background purger: removes expired pastes (DB row + blob file) and
    // GCs stale rate-limit entries.
    std::atomic<bool> stopPurger{false};
    std::thread purger([&] {
        while (!stopPurger.load()) {
            for (int i = 0; i < 60 && !stopPurger.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (stopPurger.load()) {
                break;
            }
            const auto now = util::nowSeconds();
            const auto stale = db->expiredIds(now);
            for (const auto& id : stale) {
                if (db->deletePaste(id)) {
                    const auto blobPath = cfg.blobDir + "/" + id;
                    std::error_code rmEc;
                    fs::remove(blobPath, rmEc);
                    if (rmEc) {
                        PLOGW << "purged paste " << id
                              << " but blob removal failed at " << blobPath
                              << ": " << rmEc.message();
                    } else {
                        PLOGI << "purged expired paste " << id;
                    }
                }
            }
            api.gcRateLimiter();
            api.gcSessions();
            api.gcPow();
        }
    });

    api.run();   // blocks until stop()

    stopPurger.store(true);
    if (purger.joinable()) {
        purger.join();
    }
    g_api.store(nullptr);
    PLOGI << "shutdown complete";
    return 0;
}
