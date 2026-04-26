#include "crypto.h"

#include <sodium.h>

#include <stdexcept>
#include <string>

namespace blin {

namespace {

constexpr std::size_t kEnvNonceBytes = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr std::size_t kEnvMacBytes   = crypto_aead_xchacha20poly1305_ietf_ABYTES;
constexpr std::uint8_t kEnvVersion   = 1;

constexpr std::size_t kChalPlainBytes  = 33;
constexpr std::size_t kChalCipherBytes = 49;
constexpr std::size_t kChalBurnOffset  = 32;

constexpr char kSeedAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

}  // namespace

void cryptoInit() {
    if (sodium_init() < 0) {
        throw std::runtime_error("sodium_init failed");
    }
}

Bytes deriveKey(const std::string& seed, const std::string& password) {
    const std::string saltInput = "cryptoblin/v1/" + seed;
    Bytes salt(crypto_pwhash_SALTBYTES);
    crypto_generichash(salt.data(), salt.size(),
                       reinterpret_cast<const std::uint8_t*>(saltInput.data()),
                       saltInput.size(), nullptr, 0);

    const std::string pwd = seed + ":" + password;
    Bytes out(32);
    if (crypto_pwhash(out.data(), out.size(),
                      pwd.c_str(), pwd.size(),
                      salt.data(),
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("deriveKey: out of memory");
    }
    return out;
}

Challenge makeChallenge(const Bytes& key, bool burn) {
    Challenge c;
    c.plaintext.assign(kChalPlainBytes, 0);
    randombytes_buf(c.plaintext.data(), kChalBurnOffset);
    c.plaintext[kChalBurnOffset] = burn ? 1 : 0;

    c.nonce.assign(kEnvNonceBytes, 0);
    randombytes_buf(c.nonce.data(), c.nonce.size());

    c.ciphertext.assign(kChalCipherBytes, 0);
    unsigned long long ctLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            c.ciphertext.data(), &ctLen,
            c.plaintext.data(), c.plaintext.size(),
            nullptr, 0, nullptr,
            c.nonce.data(), key.data()) != 0) {
        throw std::runtime_error("makeChallenge: encrypt failed");
    }
    c.ciphertext.resize(ctLen);
    return c;
}

Bytes solveChallenge(const Bytes& nonce, const Bytes& ciphertext, const Bytes& key) {
    if (nonce.size() != kEnvNonceBytes || ciphertext.size() < kEnvMacBytes) {
        throw std::runtime_error("solveChallenge: bad sizes");
    }
    Bytes out(ciphertext.size());
    unsigned long long ptLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            out.data(), &ptLen, nullptr,
            ciphertext.data(), ciphertext.size(),
            nullptr, 0,
            nonce.data(), key.data()) != 0) {
        throw std::runtime_error("solveChallenge: decrypt failed (wrong key/password?)");
    }
    out.resize(ptLen);
    return out;
}

Bytes sealEnvelope(const Bytes& plaintext, const Bytes& key) {
    Bytes nonce(kEnvNonceBytes);
    randombytes_buf(nonce.data(), nonce.size());

    Bytes ct(plaintext.size() + kEnvMacBytes);
    unsigned long long ctLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct.data(), &ctLen,
            plaintext.data(), plaintext.size(),
            nullptr, 0, nullptr,
            nonce.data(), key.data()) != 0) {
        throw std::runtime_error("sealEnvelope: encrypt failed");
    }
    ct.resize(ctLen);

    Bytes out(1 + kEnvNonceBytes + ct.size());
    out[0] = kEnvVersion;
    std::copy(nonce.begin(), nonce.end(), out.begin() + 1);
    std::copy(ct.begin(), ct.end(), out.begin() + 1 + kEnvNonceBytes);
    return out;
}

Bytes openEnvelope(const Bytes& env, const Bytes& key) {
    if (env.size() < 1 + kEnvNonceBytes + kEnvMacBytes) {
        throw std::runtime_error("openEnvelope: too short");
    }
    if (env[0] != kEnvVersion) {
        throw std::runtime_error("openEnvelope: unknown version");
    }
    const std::uint8_t* nonce = env.data() + 1;
    const std::uint8_t* ct    = env.data() + 1 + kEnvNonceBytes;
    const std::size_t   ctLen = env.size() - 1 - kEnvNonceBytes;

    Bytes pt(ctLen);
    unsigned long long ptLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &ptLen, nullptr,
            ct, ctLen, nullptr, 0,
            nonce, key.data()) != 0) {
        throw std::runtime_error("openEnvelope: decrypt failed");
    }
    pt.resize(ptLen);
    return pt;
}

std::string randomSeed() {
    std::string s(8, '0');
    Bytes r(8);
    randombytes_buf(r.data(), r.size());
    for (std::size_t i = 0; i < 8; ++i) {
        s[i] = kSeedAlphabet[r[i] % 62];
    }
    return s;
}

}  // namespace blin
