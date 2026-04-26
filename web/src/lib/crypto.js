// All crypto runs locally via libsodium-wrappers-sumo (WASM), so the site
// works correctly over plain http://. The server never sees the key, the
// seed, or the password.

import _sodium from 'libsodium-wrappers-sumo';

let sodium = null;
let readyPromise = null;

export function ready() {
    if (!readyPromise) {
        readyPromise = (async () => {
            await _sodium.ready;
            sodium = _sodium;
        })();
    }
    return readyPromise;
}

const KEY_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export function generateKeySeed() {
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    let out = '';
    for (let i = 0; i < 8; ++i) out += KEY_ALPHABET[bytes[i] % 62];
    return out;
}

const ENCODER = new TextEncoder();

export async function deriveKey(seed, password = '') {
    await ready();
    const salt = sodium.crypto_generichash(
        sodium.crypto_pwhash_SALTBYTES,
        ENCODER.encode('cryptoblin/v1/' + seed)
    );
    const pwd = ENCODER.encode(seed + ':' + password);
    return sodium.crypto_pwhash(
        32, pwd, salt,
        sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_ALG_ARGON2ID13
    );
}

// Proof-of-key challenge. Plaintext = 32 random + 1 burn-flag byte; the
// burn bit is AEAD-bound so the decrypter sees the value the creator set.
export const CHALLENGE_PLAIN_BYTES = 33;
export const CHALLENGE_BURN_OFFSET = 32;

export async function makeChallenge(key, { burn = false } = {}) {
    await ready();
    const plaintext = new Uint8Array(CHALLENGE_PLAIN_BYTES);
    plaintext.set(sodium.randombytes_buf(CHALLENGE_BURN_OFFSET), 0);
    plaintext[CHALLENGE_BURN_OFFSET] = burn ? 1 : 0;
    const nonce     = sodium.randombytes_buf(
        sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    );
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, null, null, nonce, key
    );
    return { plaintext, nonce, ciphertext };
}

// Decrypt a challenge served by /open. Throws on auth failure (wrong key,
// wrong password, or a decoy from the server). The caller cannot tell those
// three cases apart — that is the whole point.
export async function solveChallenge(nonceBytes, ciphertextBytes, key) {
    await ready();
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, ciphertextBytes, null, nonceBytes, key
    );
}

// Seal the (binary) payload as the encrypted blob. Output layout:
//   [VERSION byte] [NONCE bytes] [ciphertext + MAC]
// — that is what gets POSTed (after the challenge prefix) to /api/pastes.

const ENVELOPE_VERSION        = 1;        // wire-format identifier
const ENVELOPE_VERSION_BYTES  = 1;        // byte size of the version field
const ENVELOPE_NONCE_BYTES    = 24;       // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
const ENVELOPE_MAC_BYTES      = 16;       // crypto_aead_xchacha20poly1305_ietf_ABYTES
export const ENVELOPE_OVERHEAD_BYTES =
    ENVELOPE_VERSION_BYTES + ENVELOPE_NONCE_BYTES + ENVELOPE_MAC_BYTES;

const NONCE_OFFSET = ENVELOPE_VERSION_BYTES;
const CIPHER_OFFSET = ENVELOPE_VERSION_BYTES + ENVELOPE_NONCE_BYTES;

export async function sealEnvelope(plaintextBytes, key) {
    await ready();
    const nonce = sodium.randombytes_buf(ENVELOPE_NONCE_BYTES);
    const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintextBytes, null, null, nonce, key
    );
    const out = new Uint8Array(ENVELOPE_VERSION_BYTES + nonce.length + ct.length);
    out[0] = ENVELOPE_VERSION;
    out.set(nonce, NONCE_OFFSET);
    out.set(ct, CIPHER_OFFSET);
    return out;
}

export async function openEnvelope(envelopeBytes, key) {
    await ready();
    if (!envelopeBytes || envelopeBytes.length < ENVELOPE_OVERHEAD_BYTES) {
        throw new Error('envelope_too_short');
    }
    if (envelopeBytes[0] !== ENVELOPE_VERSION) throw new Error('envelope_version');
    const nonce = envelopeBytes.subarray(NONCE_OFFSET, CIPHER_OFFSET);
    const ct    = envelopeBytes.subarray(CIPHER_OFFSET);
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, ct, null, nonce, key
    );
}

export async function toB64(bytes) {
    await ready();
    return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}

export async function fromB64(s) {
    await ready();
    return sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
}
