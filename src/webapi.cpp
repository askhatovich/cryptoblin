// Copyright (C) 2026 Roman Lyubimov
// SPDX-License-Identifier: GPL-3.0-or-later

#include "webapi.h"

#include "config.h"
#include "db.h"
#include "generated_index_html.h"
#include "log.h"
#include "pow.h"
#include "util.h"
#include "version.h"

#include "crowlib/crow/json.h"
#include "sha256/sha256.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

namespace {

// Challenge plaintext = 32 random proof bytes + 1 burn-flag byte. The burn
// flag is end-to-end AEAD-authenticated, so a decrypter gets the bit the
// creator committed; the server reads it in cleartext at create time.
constexpr std::size_t kChallengePlainBytes  = 33;
constexpr std::size_t kChallengeNonceBytes  = 24;
constexpr std::size_t kChallengeCipherBytes = 49;   // 33-byte plaintext + 16-byte tag
constexpr std::size_t kChallengeBurnOffset  = 32;
constexpr std::size_t kChallengeHeaderBytes =
    kChallengePlainBytes + kChallengeNonceBytes + kChallengeCipherBytes;

constexpr auto kSessionTtl = std::chrono::seconds(60);
constexpr std::size_t kSessionsCap = 50000;

// FNV-1a over the bundle. Cheap and changes whenever the bytes do.
std::string bundleEtagFor(const std::string& html) {
    std::uint64_t h = 0xcbf29ce484222325ULL;
    for (unsigned char c : html) {
        h ^= c;
        h *= 0x100000001b3ULL;
    }
    char buf[20];
    std::snprintf(buf, sizeof(buf), "\"%016llx\"", static_cast<unsigned long long>(h));
    return buf;
}

std::string visitorIp(const crow::request& req) {
    auto takeFirst = [](std::string s) {
        if (auto c = s.find(','); c != std::string::npos) {
            s.resize(c);
        }
        std::size_t a = 0;
        while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) {
            ++a;
        }
        std::size_t b = s.size();
        while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) {
            --b;
        }
        s = s.substr(a, b - a);
        if (!s.empty() && s.front() == '[') {
            if (auto rb = s.find(']'); rb != std::string::npos) {
                s = s.substr(1, rb - 1);
            }
        } else if (std::count(s.begin(), s.end(), ':') == 1) {
            s.resize(s.find(':'));
        }
        if (s.size() > 64) {
            s.resize(64);
        }
        return s;
    };
    auto xff = req.get_header_value("X-Forwarded-For");
    if (!xff.empty()) {
        return takeFirst(xff);
    }
    auto xri = req.get_header_value("X-Real-IP");
    if (!xri.empty()) {
        return takeFirst(xri);
    }
    return req.remote_ip_address;
}

crow::response jsonError(int status, const char* code, const char* msg = nullptr) {
    crow::json::wvalue v;
    v["error_code"] = code;
    if (msg) {
        v["message"] = msg;
    }
    crow::response r{status, v};
    r.add_header("Content-Type", "application/json");
    return r;
}

bool isValidPasteId(const std::string& s) {
    if (s.size() != 8) {
        return false;
    }
    for (char c : s) {
        if (!std::isalnum(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

std::string blobPath(const std::string& id) {
    return Config::instance().blobDir + "/" + id;
}

bool writeBlobAtomic(const std::string& id, const char* data, std::size_t n) {
    const auto& dir = Config::instance().blobDir;
    std::error_code ec;
    fs::create_directories(dir, ec);
    const auto target = blobPath(id);
    const auto tmp    = target + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) {
            return false;
        }
        f.write(data, static_cast<std::streamsize>(n));
        if (!f) {
            return false;
        }
    }
    fs::rename(tmp, target, ec);
    if (ec) {
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

std::optional<std::string> readBlob(const std::string& id) {
    std::ifstream f(blobPath(id), std::ios::binary);
    if (!f) {
        return std::nullopt;
    }
    std::string out((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return out;
}

void unlinkBlob(const std::string& id) {
    const auto path = blobPath(id);
    std::error_code ec;
    const bool removed = fs::remove(path, ec);
    if (ec) {
        PLOGW << "blob removal failed at " << path << ": " << ec.message();
    } else if (!removed) {
        // Row had no blob on disk (orphan or already gone). Not fatal.
        PLOGW << "blob missing at " << path << " for id " << id;
    }
}

std::vector<std::uint8_t> sha256(const std::vector<std::uint8_t>& data) {
    tools::SHA256 h;
    h.update(data);
    auto d = h.digest();
    return std::vector<std::uint8_t>(d.begin(), d.end());
}

std::string js_str(const crow::json::rvalue& v, const char* key) {
    if (v.has(key) && v[key].t() == crow::json::type::String) {
        return std::string(v[key].s());
    }
    return {};
}

}  // namespace

WebAPI::WebAPI(Database& db) : db_(db) {
    bundleHtml_ = getIndexHtml();
    bundleEtag_ = bundleEtagFor(bundleHtml_);

    const auto& cfg = Config::instance();
    auto secretBytes = util::randomBytes(32);
    std::string secret(reinterpret_cast<const char*>(secretBytes.data()), secretBytes.size());
    pow_ = std::make_unique<captcha::ChallengeIssuer>(
        std::move(secret),
        static_cast<unsigned>(cfg.powDifficultyBits),
        std::chrono::seconds(cfg.powTtlSeconds));

    initRoutes();
}

void WebAPI::run() {
    auto& cfg = Config::instance();
    app_.signal_clear();
    app_.bindaddr(cfg.bindAddress).port(cfg.bindPort).multithreaded().run();
}

void WebAPI::stop() { app_.stop(); }

bool WebAPI::rateLimitAdmit(const std::string& ip) {
    auto& cfg = Config::instance();
    if (cfg.rateLimitPerIpSeconds <= 0 || ip.empty()) {
        return true;
    }
    const auto now = std::chrono::steady_clock::now();
    const auto window = std::chrono::seconds(cfg.rateLimitPerIpSeconds);
    std::lock_guard<std::mutex> lk(rateLimitMu_);
    auto it = lastSeen_.find(ip);
    if (it != lastSeen_.end() && now - it->second < window) {
        return false;
    }
    lastSeen_[ip] = now;
    return true;
}

void WebAPI::gcRateLimiter() {
    const auto now = std::chrono::steady_clock::now();
    const auto cutoff = std::chrono::seconds(60);
    std::lock_guard<std::mutex> lk(rateLimitMu_);
    for (auto it = lastSeen_.begin(); it != lastSeen_.end();) {
        if (now - it->second > cutoff) {
            it = lastSeen_.erase(it);
        } else {
            ++it;
        }
    }
}

void WebAPI::gcPow() {
    if (pow_) {
        pow_->gcReplay();
    }
}

void WebAPI::gcSessions() {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(sessionsMu_);
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (it->second.expiresAt <= now) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
    // Hard cap: drop arbitrary entries to bound memory under abuse.
    while (sessions_.size() > kSessionsCap) {
        sessions_.erase(sessions_.begin());
    }
}

void WebAPI::initRoutes() {
    // --- Static SPA bundle. ---
    const auto serveBundle = [this](const crow::request& req) {
        const auto inm = req.get_header_value("If-None-Match");
        if (!inm.empty() && inm == bundleEtag_) {
            crow::response r304(304);
            r304.add_header("ETag", bundleEtag_);
            r304.add_header("Cache-Control", "public, max-age=0, must-revalidate");
            return r304;
        }
        crow::response r{bundleHtml_};
        r.add_header("Content-Type", "text/html; charset=utf-8");
        r.add_header("ETag", bundleEtag_);
        r.add_header("Cache-Control", "public, max-age=0, must-revalidate");
        return r;
    };
    CROW_ROUTE(app_, "/")
    ([serveBundle](const crow::request& req) { return serveBundle(req); });

    // --- Public app config. ---
    CROW_ROUTE(app_, "/api/config")
    ([this]() {
        const auto& c = Config::instance();
        crow::json::wvalue v;
        v["app_name"]        = c.appName;
        v["title"]           = c.title.empty() ? c.appName : c.title;
        v["version"]         = std::string(CRYPTOBLIN_VERSION);
        v["max_paste_bytes"] = c.maxPasteBytes;
        v["min_ttl_seconds"] = c.minTtlSeconds;
        v["max_ttl_seconds"] = c.maxTtlSeconds;
        crow::response r{v};
        r.add_header("Content-Type", "application/json");
        return r;
    });

    // --- Issue a fresh proof-of-work captcha. Rate-limited per-IP so a
    //     single client cannot exhaust replay-set memory by spinning up
    //     captchas faster than it solves them. Reads (/open, /blob) stay
    //     unrestricted — opening multiple existing pastes is normal use.
    CROW_ROUTE(app_, "/api/captcha")
    ([this](const crow::request& req) {
        const auto ip = visitorIp(req);
        if (!rateLimitAdmit(ip)) {
            return jsonError(429, "rate_limited");
        }
        const auto c = pow_->issue();
        crow::json::wvalue v;
        v["token"]      = c.token;
        v["difficulty"] = c.difficultyBits;
        v["expires_at"] = c.expiresUnix;
        crow::response r{v};
        r.add_header("Content-Type", "application/json");
        return r;
    });

    // --- Create paste. Body layout (binary octet-stream):
    //       [32 bytes plaintext] [24 bytes nonce] [48 bytes ciphertext] [N bytes blob]
    //     where the plaintext/nonce/ciphertext triple is the proof-of-key
    //     challenge generated client-side. The server stores it verbatim.
    CROW_ROUTE(app_, "/api/pastes").methods(crow::HTTPMethod::POST)
    ([this](const crow::request& req) {
        const auto& c = Config::instance();

        // Proof-of-work gate. Carried in headers because the body is a
        // raw octet-stream — no room for query-string smuggling and we
        // want the gate to reject before we read the (potentially large)
        // body all the way through.
        const auto powToken = req.get_header_value("X-Pow-Token");
        const auto powNonce = req.get_header_value("X-Pow-Nonce");
        if (powToken.empty() || powNonce.empty()) {
            return jsonError(403, "pow_required");
        }
        switch (pow_->verifyAndConsume(powToken, powNonce)) {
            case captcha::VerifyResult::Ok: {
                break;
            }
            case captcha::VerifyResult::Malformed:
            case captcha::VerifyResult::BadSignature: {
                return jsonError(403, "pow_invalid");
            }
            case captcha::VerifyResult::Expired: {
                return jsonError(403, "pow_expired");
            }
            case captcha::VerifyResult::InsufficientWork: {
                return jsonError(403, "pow_insufficient");
            }
            case captcha::VerifyResult::Replay: {
                return jsonError(403, "pow_replayed");
            }
        }

        const auto& body = req.body;
        if (body.size() <= kChallengeHeaderBytes) {
            return jsonError(400, "empty_body");
        }
        const std::size_t blobLen = body.size() - kChallengeHeaderBytes;
        if (static_cast<std::int64_t>(blobLen) > c.maxPasteBytes) {
            return jsonError(413, "too_large");
        }
        if (c.totalPastesCap > 0 && db_.pasteCount() >= c.totalPastesCap) {
            return jsonError(503, "capacity_full");
        }
        PasteChallenge ch;
        const auto* p = reinterpret_cast<const std::uint8_t*>(body.data());
        ch.plaintext  = std::vector<std::uint8_t>(p, p + kChallengePlainBytes);
        ch.nonce      = std::vector<std::uint8_t>(p + kChallengePlainBytes,
                                                  p + kChallengePlainBytes + kChallengeNonceBytes);
        ch.ciphertext = std::vector<std::uint8_t>(p + kChallengePlainBytes + kChallengeNonceBytes,
                                                  p + kChallengeHeaderBytes);

        const bool burn = ch.plaintext[kChallengeBurnOffset] != 0;

        std::string id;
        for (int attempt = 0; attempt < 5; ++attempt) {
            const auto candidate = util::randomPasteId();
            if (!db_.getMeta(candidate)) {
                id = candidate;
                break;
            }
        }
        if (id.empty()) {
            return jsonError(500, "id_alloc_failed");
        }

        if (!writeBlobAtomic(id, body.data() + kChallengeHeaderBytes, blobLen)) {
            return jsonError(500, "blob_write_failed");
        }

        const auto now = util::nowSeconds();
        const auto ttl = util::ttlForSize(static_cast<std::int64_t>(blobLen),
                                          c.maxPasteBytes, c.minTtlSeconds, c.maxTtlSeconds);
        PasteMeta meta;
        meta.id        = id;
        meta.createdAt = now;
        meta.expiresAt = now + ttl;
        meta.sizeBytes = static_cast<std::int64_t>(blobLen);
        meta.burn      = burn;
        // Owner-only delete capability: 16 random bytes returned to the
        // creator once. Server stores SHA-256(token); a future DELETE request
        // sends the token, server hashes and constant-time-compares.
        const auto deleteTokenBytes = util::randomBytes(16);
        const auto deleteTokenB64   = util::base64Encode(deleteTokenBytes);
        const auto deleteTokenHash  = sha256(deleteTokenBytes);

        try {
            db_.insertPaste(meta, ch, deleteTokenHash);
        } catch (const std::exception& e) {
            unlinkBlob(id);
            PLOGE << "insertPaste: " << e.what();
            return jsonError(500, "db_insert_failed");
        }

        crow::json::wvalue v;
        v["id"]           = id;
        v["created_at"]   = meta.createdAt;
        v["expires_at"]   = meta.expiresAt;
        v["size"]         = meta.sizeBytes;
        v["ttl_seconds"]  = ttl;
        v["burn"]         = burn;
        v["delete_token"] = deleteTokenB64;
        crow::response r{201, v};
        r.add_header("Content-Type", "application/json");
        return r;
    });

    // --- Open: returns only a challenge (token + nonce + ciphertext). The
    //     same shape is returned for non-existent ids (decoy). All meta is
    //     withheld until /blob proves the caller owns the key.
    CROW_ROUTE(app_, "/api/pastes/<string>/open").methods(crow::HTTPMethod::POST)
    ([this](const crow::request& req, const std::string& id) {
        // No rate limit here: opening pastes is a read path and reading
        // several in a row (e.g. clicking links from chat) must not 429.
        (void)req;
        if (!isValidPasteId(id)) {
            return jsonError(400, "bad_id");
        }

        std::string token = util::randomTokenHex();
        crow::json::wvalue out;
        crow::json::wvalue chal;

        ChallengeSession sess;
        sess.expiresAt = std::chrono::steady_clock::now() + kSessionTtl;

        auto pasteCh = db_.getChallenge(id);
        if (pasteCh) {
            sess.realId = id;
            sess.expectedPlaintext = pasteCh->plaintext;
            chal["nonce"]      = util::base64Encode(pasteCh->nonce);
            chal["ciphertext"] = util::base64Encode(pasteCh->ciphertext);
        } else {
            sess.realId.clear();
            sess.expectedPlaintext = util::randomBytes(kChallengePlainBytes);
            chal["nonce"]      = util::base64Encode(util::randomBytes(kChallengeNonceBytes));
            chal["ciphertext"] = util::base64Encode(util::randomBytes(kChallengeCipherBytes));
        }

        {
            std::lock_guard<std::mutex> lk(sessionsMu_);
            sessions_[token] = std::move(sess);
        }

        out["token"]     = token;
        out["challenge"] = std::move(chal);
        crow::response r{out};
        r.add_header("Content-Type", "application/json");
        return r;
    });

    // --- Blob: requires (token, plaintext_b64) returned/decrypted from /open.
    //     On match: streams the blob bytes; if `burn` was set, atomically
    //     deletes the row so a parallel reader sees 404.
    CROW_ROUTE(app_, "/api/pastes/<string>/blob").methods(crow::HTTPMethod::POST)
    ([this](const crow::request& req, const std::string& id) {
        // Read path, no rate limit (see /open). Abuse here is bounded by
        // the single-use challenge token + replay set on /open anyway.
        if (!isValidPasteId(id)) {
            return jsonError(400, "bad_id");
        }

        const auto js = crow::json::load(req.body);
        if (!js) {
            return jsonError(400, "bad_json");
        }
        const auto token = js_str(js, "token");
        const auto pb64  = js_str(js, "plaintext");
        if (token.empty() || pb64.empty()) {
            return jsonError(403, "bad_key");
        }

        bool ok = false;
        const auto plaintext = util::base64Decode(pb64, &ok);
        if (!ok || plaintext.size() != kChallengePlainBytes) {
            return jsonError(403, "bad_key");
        }

        ChallengeSession sess;
        {
            std::lock_guard<std::mutex> lk(sessionsMu_);
            auto it = sessions_.find(token);
            if (it == sessions_.end() ||
                it->second.expiresAt <= std::chrono::steady_clock::now()) {
                return jsonError(403, "bad_key");
            }
            sess = std::move(it->second);
            sessions_.erase(it);   // single-use
        }

        // Wrong id / decoy / wrong plaintext all collapse to the same error.
        if (sess.realId != id) {
            return jsonError(403, "bad_key");
        }
        if (!util::ctEqual(sess.expectedPlaintext, plaintext)) {
            return jsonError(403, "bad_key");
        }

        auto meta = db_.getMeta(id);
        if (!meta) {
            return jsonError(403, "bad_key");
        }

        if (meta->burn) {
            // Atomic claim: only one /blob call wins the DELETE.
            if (!db_.deletePaste(id)) {
                return jsonError(403, "bad_key");
            }
            auto blob = readBlob(id);
            unlinkBlob(id);
            if (!blob) {
                return jsonError(403, "bad_key");
            }
            crow::response r{*blob};
            r.add_header("Content-Type", "application/octet-stream");
            r.add_header("Content-Length", std::to_string(blob->size()));
            r.add_header("X-View-Count", "1");
            r.add_header("X-Burned", "1");
            r.add_header("X-Created-At", std::to_string(meta->createdAt));
            r.add_header("X-Expires-At", std::to_string(meta->expiresAt));
            return r;
        }

        auto blob = readBlob(id);
        if (!blob) {
            return jsonError(403, "bad_key");
        }
        const auto views = db_.incrementViewCount(id);
        crow::response r{*blob};
        r.add_header("Content-Type", "application/octet-stream");
        r.add_header("Content-Length", std::to_string(blob->size()));
        r.add_header("X-View-Count", std::to_string(views));
        r.add_header("X-Burned", "0");
        r.add_header("X-Created-At", std::to_string(meta->createdAt));
        r.add_header("X-Expires-At", std::to_string(meta->expiresAt));
        return r;
    });

    // --- Owner delete: token issued at create time. We hash the submitted
    //     token and constant-time-compare against the stored hash inside
    //     the DB layer. Missing/wrong token, missing id, expired paste —
    //     all collapse to 403 bad_token without distinguishable timing.
    CROW_ROUTE(app_, "/api/pastes/<string>").methods(crow::HTTPMethod::Delete)
    ([this](const crow::request& req, const std::string& id) {
        if (!isValidPasteId(id)) {
            return jsonError(400, "bad_id");
        }
        const auto tokenB64 = req.get_header_value("X-Delete-Token");
        if (tokenB64.empty()) {
            return jsonError(403, "bad_token");
        }
        bool ok = false;
        const auto tokenBytes = util::base64Decode(tokenB64, &ok);
        if (!ok || tokenBytes.empty()) {
            return jsonError(403, "bad_token");
        }
        const auto tokenHash = sha256(tokenBytes);
        if (!db_.deleteWithToken(id, tokenHash)) {
            return jsonError(403, "bad_token");
        }
        unlinkBlob(id);
        crow::json::wvalue v;
        v["deleted"] = true;
        crow::response r{200, v};
        r.add_header("Content-Type", "application/json");
        return r;
    });
}
