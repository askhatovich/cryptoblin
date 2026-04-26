// Proof-of-work solver. Run between hitting "Submit" and uploading the
// paste, so single-shot abuse of /api/pastes costs the attacker real CPU.
//
// We re-use libsodium's WASM SHA-256 (already loaded for the AEAD path)
// instead of a hand-rolled JS implementation — it is 10× faster and
// avoids carrying two SHA-256 sources in the bundle.

import _sodium from 'libsodium-wrappers-sumo';

let sodium = null;
async function ready() {
    if (!sodium) { await _sodium.ready; sodium = _sodium; }
    return sodium;
}

const ENC = new TextEncoder();

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

// Find a nonce (decimal ASCII string) such that
// SHA-256(token + ":" + nonce) has at least `difficulty` leading zero bits.
//
// Loop is chunked so the UI stays responsive: every BATCH iterations we
// yield via `setTimeout(0)` and call `onProgress(tries)` if provided.
//
// Returns the nonce string. Difficulty above ~24 bits will block for
// noticeable seconds even after libsodium's WASM speedup; the server caps
// it at 32 bits.
export async function solve(token, difficulty, onProgress) {
    await ready();
    const prefix = ENC.encode(token + ':');

    let n = 0;
    const BATCH = 2000;
    while (true) {
        for (let i = 0; i < BATCH; ++i) {
            const ns = String(n);
            const buf = new Uint8Array(prefix.length + ns.length);
            buf.set(prefix);
            for (let j = 0; j < ns.length; ++j) buf[prefix.length + j] = ns.charCodeAt(j);
            const d = sodium.crypto_hash_sha256(buf);
            if (leadingZeroBits(d) >= difficulty) return ns;
            ++n;
        }
        if (onProgress) onProgress(n);
        await new Promise(r => setTimeout(r, 0));
    }
}
