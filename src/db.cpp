// Copyright (C) 2026 Roman Lyubimov
// SPDX-License-Identifier: GPL-3.0-or-later

#include "db.h"

#include "util.h"

#include <sqlite3.h>

#include <stdexcept>
#include <string>

namespace {

void exec(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown sqlite error";
        sqlite3_free(err);
        throw std::runtime_error("sqlite_exec failed: " + msg);
    }
}

std::vector<std::uint8_t> readBlobCol(sqlite3_stmt* stmt, int col) {
    const auto* p = static_cast<const std::uint8_t*>(sqlite3_column_blob(stmt, col));
    const int n = sqlite3_column_bytes(stmt, col);
    return std::vector<std::uint8_t>(p, p + n);
}

}  // namespace

std::unique_ptr<Database> Database::open(const std::string& path) {
    auto out = std::unique_ptr<Database>(new Database());
    if (sqlite3_open(path.c_str(), &out->db_) != SQLITE_OK) {
        const std::string msg = sqlite3_errmsg(out->db_);
        sqlite3_close(out->db_);
        throw std::runtime_error("cannot open db " + path + ": " + msg);
    }
    exec(out->db_, "PRAGMA journal_mode=WAL;");
    exec(out->db_, "PRAGMA synchronous=NORMAL;");
    exec(out->db_, "PRAGMA foreign_keys=ON;");
    exec(out->db_,
        "CREATE TABLE IF NOT EXISTS pastes ("
        "  id TEXT PRIMARY KEY,"
        "  created_at INTEGER NOT NULL,"
        "  expires_at INTEGER NOT NULL,"
        "  size_bytes INTEGER NOT NULL,"
        "  burn INTEGER NOT NULL DEFAULT 0,"
        "  view_count INTEGER NOT NULL DEFAULT 0,"
        "  ch_plain  BLOB NOT NULL,"
        "  ch_nonce  BLOB NOT NULL,"
        "  ch_cipher BLOB NOT NULL,"
        "  delete_token_hash BLOB NOT NULL"
        ");");
    exec(out->db_,
        "CREATE INDEX IF NOT EXISTS pastes_expires ON pastes(expires_at);");
    return out;
}

Database::~Database() {
    if (db_) {
        sqlite3_close(db_);
    }
}

void Database::insertPaste(const PasteMeta& meta, const PasteChallenge& ch,
                           const std::vector<std::uint8_t>& deleteTokenHash) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
            "INSERT INTO pastes(id, created_at, expires_at, size_bytes, burn, view_count, "
            "ch_plain, ch_nonce, ch_cipher, delete_token_hash) "
            "VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)",
            -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(db_));
    }
    sqlite3_bind_text (stmt, 1, meta.id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, meta.createdAt);
    sqlite3_bind_int64(stmt, 3, meta.expiresAt);
    sqlite3_bind_int64(stmt, 4, meta.sizeBytes);
    sqlite3_bind_int  (stmt, 5, meta.burn ? 1 : 0);
    sqlite3_bind_blob (stmt, 6, ch.plaintext.data(),  static_cast<int>(ch.plaintext.size()),  SQLITE_TRANSIENT);
    sqlite3_bind_blob (stmt, 7, ch.nonce.data(),      static_cast<int>(ch.nonce.size()),      SQLITE_TRANSIENT);
    sqlite3_bind_blob (stmt, 8, ch.ciphertext.data(), static_cast<int>(ch.ciphertext.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob (stmt, 9, deleteTokenHash.data(),
                       static_cast<int>(deleteTokenHash.size()), SQLITE_TRANSIENT);
    const int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        throw std::runtime_error("insertPaste failed");
    }
}

bool Database::deleteWithToken(const std::string& id,
                               const std::vector<std::uint8_t>& tokenHash) {
    // Read the row's stored hash and compare in constant time, then DELETE
    // by id only on match. This avoids leaking timing info via SQL.
    sqlite3_stmt* sel = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT delete_token_hash FROM pastes WHERE id = ?",
            -1, &sel, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(sel, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    std::vector<std::uint8_t> stored;
    if (sqlite3_step(sel) == SQLITE_ROW) {
        stored = readBlobCol(sel, 0);
    }
    sqlite3_finalize(sel);
    if (stored.empty()) {
        return false;
    }
    if (!util::ctEqual(stored, tokenHash)) {
        return false;
    }
    return deletePaste(id);
}

std::optional<PasteMeta> Database::getMeta(const std::string& id) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT id, created_at, expires_at, size_bytes, burn, view_count "
            "FROM pastes WHERE id = ?",
            -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<PasteMeta> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        PasteMeta m;
        m.id        = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        m.createdAt = sqlite3_column_int64(stmt, 1);
        m.expiresAt = sqlite3_column_int64(stmt, 2);
        m.sizeBytes = sqlite3_column_int64(stmt, 3);
        m.burn      = sqlite3_column_int  (stmt, 4) != 0;
        m.viewCount = sqlite3_column_int64(stmt, 5);
        result = m;
    }
    sqlite3_finalize(stmt);
    if (result && result->expiresAt > 0 && result->expiresAt <= util::nowSeconds()) {
        return std::nullopt;
    }
    return result;
}

std::optional<PasteChallenge> Database::getChallenge(const std::string& id) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT ch_plain, ch_nonce, ch_cipher FROM pastes WHERE id = ?",
            -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<PasteChallenge> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        PasteChallenge c;
        c.plaintext  = readBlobCol(stmt, 0);
        c.nonce      = readBlobCol(stmt, 1);
        c.ciphertext = readBlobCol(stmt, 2);
        result = std::move(c);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::int64_t Database::incrementViewCount(const std::string& id) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
            "UPDATE pastes SET view_count = view_count + 1 WHERE id = ? RETURNING view_count",
            -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    std::int64_t out = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return out;
}

bool Database::deletePaste(const std::string& id) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
            "DELETE FROM pastes WHERE id = ?",
            -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    const int rc = sqlite3_step(stmt);
    const int changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && changes > 0;
}

std::vector<std::string> Database::expiredIds(std::int64_t cutoff) {
    std::vector<std::string> out;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT id FROM pastes WHERE expires_at > 0 AND expires_at <= ?",
            -1, &stmt, nullptr) != SQLITE_OK) {
        return out;
    }
    sqlite3_bind_int64(stmt, 1, cutoff);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        out.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    }
    sqlite3_finalize(stmt);
    return out;
}

std::int64_t Database::pasteCount() {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM pastes",
                           -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    std::int64_t n = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        n = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return n;
}
