// Copyright (C) 2026 Roman Lyubimov
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

struct PasteMeta {
    std::string  id;
    std::int64_t createdAt = 0;
    std::int64_t expiresAt = 0;
    std::int64_t sizeBytes = 0;
    bool         burn      = false;
    std::int64_t viewCount = 0;
};

// One-shot proof-of-key triple uploaded by the creator. The server stores
// these bytes verbatim — it cannot decrypt them and uses them only to verify
// that an opener has the right key (XChaCha20-Poly1305 authenticated decrypt
// of `cipher` under that key must produce `plaintext`).
struct PasteChallenge {
    std::vector<std::uint8_t> plaintext;   // 32 bytes
    std::vector<std::uint8_t> nonce;       // 24 bytes
    std::vector<std::uint8_t> ciphertext;  // 48 bytes (32-byte plaintext + 16-byte tag)
};

class Database {
public:
    static std::unique_ptr<Database> open(const std::string& path);
    ~Database();

    void insertPaste(const PasteMeta& meta, const PasteChallenge& ch,
                     const std::vector<std::uint8_t>& deleteTokenHash);

    std::optional<PasteMeta>      getMeta(const std::string& id);
    std::optional<PasteChallenge> getChallenge(const std::string& id);

    std::int64_t incrementViewCount(const std::string& id);
    bool         deletePaste(const std::string& id);
    // Returns true if a row with matching id+hashed-token existed and was
    // deleted. The compare is constant-time.
    bool         deleteWithToken(const std::string& id,
                                 const std::vector<std::uint8_t>& tokenHash);

    std::vector<std::string> expiredIds(std::int64_t cutoff);
    std::int64_t             pasteCount();

private:
    Database() = default;
    sqlite3* db_ = nullptr;
};
