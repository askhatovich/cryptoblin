// End-to-end test helpers. Mirror exactly what the browser does in
// src/lib/{crypto,payload,api}.js so the test exercises the same wire
// format the real frontend produces.

import _sodium from 'libsodium-wrappers-sumo';

let sodium = null;
export async function ready() {
    if (!sodium) { await _sodium.ready; sodium = _sodium; }
    return sodium;
}

const ENC = new TextEncoder();
const DEC = new TextDecoder();

// Mirrors src/lib/payload.js — text + optional file in the same envelope.
export const FORMAT = { TEXT: 0, MARKDOWN: 1, CODE: 2 };

// Wire-layout sizes — kept in sync with src/lib/{crypto,payload}.js.
const ENVELOPE_VERSION         = 1;
const ENVELOPE_VERSION_BYTES   = 1;
const ENVELOPE_NONCE_BYTES     = 24;   // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
const NONCE_OFFSET             = ENVELOPE_VERSION_BYTES;
const CIPHER_OFFSET            = ENVELOPE_VERSION_BYTES + ENVELOPE_NONCE_BYTES;

const FORMAT_BYTE_BYTES        = 1;    // single-byte format selector
const SHORT_LEN_BYTES          = 2;    // u16 BE length prefix
const LONG_LEN_BYTES           = 4;    // u32 BE length prefix

export function randomSeed() {
    const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = new Uint8Array(8);
    require_crypto().getRandomValues(bytes);
    let out = '';
    for (let i = 0; i < 8; ++i) out += ALPHABET[bytes[i] % 62];
    return out;
}
function require_crypto() {
    // Node 18+ exposes globalThis.crypto with WebCrypto getRandomValues.
    if (!globalThis.crypto?.getRandomValues) {
        throw new Error('global crypto missing — needs Node 18+');
    }
    return globalThis.crypto;
}

export async function deriveKey(seed, password = '') {
    await ready();
    const salt = sodium.crypto_generichash(
        sodium.crypto_pwhash_SALTBYTES,
        ENC.encode('cryptoblin/v1/' + seed)
    );
    return sodium.crypto_pwhash(
        32,
        ENC.encode(seed + ':' + password),
        salt,
        sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_ALG_ARGON2ID13
    );
}

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

export async function solveChallenge(nonce, ciphertext, key) {
    await ready();
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, ciphertext, null, nonce, key
    );
}

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

export async function openEnvelope(envelope, key) {
    await ready();
    const nonce = envelope.subarray(NONCE_OFFSET, CIPHER_OFFSET);
    const ct    = envelope.subarray(CIPHER_OFFSET);
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, ct, null, nonce, key
    );
}

export function packPayload({ format = FORMAT.TEXT, lang = '', text = '', file = null }) {
    const langB = ENC.encode(lang || '');
    const textB = typeof text === 'string' ? ENC.encode(text)
                : (text instanceof Uint8Array ? text : new Uint8Array(0));
    const nameB = ENC.encode(file?.name || '');
    const mimeB = ENC.encode(file?.mime || '');
    const fileB = file?.body instanceof Uint8Array ? file.body : new Uint8Array(0);

    const total = FORMAT_BYTE_BYTES
        + SHORT_LEN_BYTES + langB.length
        + LONG_LEN_BYTES  + textB.length
        + SHORT_LEN_BYTES + nameB.length
        + SHORT_LEN_BYTES + mimeB.length
        + LONG_LEN_BYTES  + fileB.length;

    const out = new Uint8Array(total);
    const view = new DataView(out.buffer);
    let o = 0;
    out[o] = format & 0xff; o += FORMAT_BYTE_BYTES;
    view.setUint16(o, langB.length, false); o += SHORT_LEN_BYTES; out.set(langB, o); o += langB.length;
    view.setUint32(o, textB.length, false); o += LONG_LEN_BYTES;  out.set(textB, o); o += textB.length;
    view.setUint16(o, nameB.length, false); o += SHORT_LEN_BYTES; out.set(nameB, o); o += nameB.length;
    view.setUint16(o, mimeB.length, false); o += SHORT_LEN_BYTES; out.set(mimeB, o); o += mimeB.length;
    view.setUint32(o, fileB.length, false); o += LONG_LEN_BYTES;  out.set(fileB, o); o += fileB.length;
    return out;
}

export function unpackPayload(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let o = 0;
    const format = bytes[o]; o += FORMAT_BYTE_BYTES;
    const langLen = view.getUint16(o, false); o += SHORT_LEN_BYTES;
    const lang = DEC.decode(bytes.subarray(o, o + langLen)); o += langLen;
    const textLen = view.getUint32(o, false); o += LONG_LEN_BYTES;
    const text = DEC.decode(bytes.subarray(o, o + textLen)); o += textLen;
    const nameLen = view.getUint16(o, false); o += SHORT_LEN_BYTES;
    const name = DEC.decode(bytes.subarray(o, o + nameLen)); o += nameLen;
    const mimeLen = view.getUint16(o, false); o += SHORT_LEN_BYTES;
    const mime = DEC.decode(bytes.subarray(o, o + mimeLen)); o += mimeLen;
    const fileLen = view.getUint32(o, false); o += LONG_LEN_BYTES;
    const fileBody = bytes.subarray(o, o + fileLen);
    const hasFile = nameLen > 0 || mimeLen > 0 || fileLen > 0;
    return {
        format, lang, text,
        file: hasFile ? { name, mime, body: new Uint8Array(fileBody) } : null
    };
}

export async function toB64(bytes) {
    await ready();
    return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}
export async function fromB64(s) {
    await ready();
    return sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
}

// SHA-256 helper used by the PoW solver. We use libsodium's WASM SHA-256
// so we don't carry a pure-JS implementation in test code.
export async function sha256(bytes) {
    await ready();
    return sodium.crypto_hash_sha256(bytes);
}

function leadingZeroBits(bytes) {
    let n = 0;
    for (const b of bytes) {
        if (b === 0) { n += 8; continue; }
        for (let i = 7; i >= 0; --i) {
            if ((b >> i) & 1) return n;
            ++n;
        }
        return n;
    }
    return n;
}

// Brute-force a nonce that makes SHA-256(token + ":" + nonce) clear
// `difficulty` leading zero bits. Synchronous in spirit — tests pick the
// difficulty so they can assume sub-second completion.
export async function solvePow(token, difficulty) {
    await ready();
    const prefix = ENC.encode(token + ':');
    for (let n = 0; ; ++n) {
        const ns = String(n);
        const buf = new Uint8Array(prefix.length + ns.length);
        buf.set(prefix);
        for (let j = 0; j < ns.length; ++j) buf[prefix.length + j] = ns.charCodeAt(j);
        const d = sodium.crypto_hash_sha256(buf);
        if (leadingZeroBits(d) >= difficulty) return ns;
    }
}

// Build the full POST body the server expects on /api/pastes:
//   [33 plaintext | 24 nonce | 49 cipher | sealed envelope]
export function buildCreateBody(challenge, envelope) {
    const total = new Uint8Array(
        challenge.plaintext.length +
        challenge.nonce.length +
        challenge.ciphertext.length +
        envelope.length
    );
    let o = 0;
    total.set(challenge.plaintext, o); o += challenge.plaintext.length;
    total.set(challenge.nonce, o);     o += challenge.nonce.length;
    total.set(challenge.ciphertext, o); o += challenge.ciphertext.length;
    total.set(envelope, o);
    return total;
}
