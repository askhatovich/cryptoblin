#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace blin {

using Bytes = std::vector<std::uint8_t>;

void cryptoInit();

// Argon2id KDF matching the web client:
//   salt = blake2b("cryptoblin/v1/" + seed)
//   pwd  = seed + ":" + password
//   key  = argon2id(pwd, salt, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE)
Bytes deriveKey(const std::string& seed, const std::string& password);

struct Challenge {
    Bytes plaintext;   // 33 bytes (32 random + 1 burn flag)
    Bytes nonce;       // 24 bytes
    Bytes ciphertext;  // 49 bytes
};

Challenge makeChallenge(const Bytes& key, bool burn);
Bytes     solveChallenge(const Bytes& nonce, const Bytes& ciphertext, const Bytes& key);

// Outer envelope around the user payload:
//   [1 byte version=1][24 byte nonce][ciphertext + 16 byte tag]
Bytes sealEnvelope(const Bytes& plaintext, const Bytes& key);
Bytes openEnvelope(const Bytes& envelope, const Bytes& key);

// 8-character base62 seed (URL fragment portion).
std::string randomSeed();

}  // namespace blin
