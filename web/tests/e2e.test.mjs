// End-to-end tests for cryptoblin. Spawns the real binary, exercises
// every public route through the same crypto path the browser uses, and
// asserts the security properties (decoy for unknown id, single-use
// challenge token, burn-after-read race winner, view counter monotonic,
// rate-limit gate).
//
// Run with:    cd web && node --test tests/
//
// Requires:   ../build/src/cryptoblin (build first).

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as wait } from 'node:timers/promises';

import {
    ready, randomSeed, deriveKey, makeChallenge, solveChallenge,
    sealEnvelope, openEnvelope, packPayload, unpackPayload,
    toB64, fromB64, buildCreateBody, solvePow, FORMAT
} from './proto.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BINARY    = resolve(__dirname, '../../build/src/cryptoblin');

// Pick a port outside the usual ephemeral pool to keep restart-after-crash
// quick (no TIME_WAIT collision with normal traffic).
function pickPort() { return 19000 + Math.floor(Math.random() * 1000); }

class Server {
    constructor({ rateLimitSeconds = 0, totalCap = 0, powDifficulty = 6 } = {}) {
        this.dir = mkdtempSync(join(tmpdir(), 'cryptoblin-test-'));
        this.port = pickPort();
        this.base = `http://127.0.0.1:${this.port}`;
        this.powDifficulty = powDifficulty;
        const cfg = `
[server]
log_level = warning
bind_address = 127.0.0.1
bind_port = ${this.port}
app_name = TestBin

[storage]
db_path  = ${this.dir}/test.sqlite
blob_dir = ${this.dir}/blobs

[retention]
max_paste_bytes = 1048576
min_ttl_seconds = 60
max_ttl_seconds = 3600

[limits]
rate_limit_per_ip_seconds = ${rateLimitSeconds}
total_pastes_cap = ${totalCap}

[captcha]
difficulty_bits = ${powDifficulty}
ttl_seconds = 300
`;
        writeFileSync(join(this.dir, 'config.ini'), cfg);
        this.proc = spawn(BINARY, ['--config', join(this.dir, 'config.ini')], {
            stdio: ['ignore', 'ignore', 'inherit']
        });
    }

    async ready() {
        const deadline = Date.now() + 5000;
        while (Date.now() < deadline) {
            try {
                const r = await fetch(this.base + '/api/config');
                if (r.ok) return;
            } catch { /* not yet listening */ }
            await wait(50);
        }
        throw new Error('server failed to start');
    }

    async stop() {
        if (this.proc && !this.proc.killed) {
            this.proc.kill('SIGTERM');
            await new Promise(res => this.proc.once('exit', res));
        }
        rmSync(this.dir, { recursive: true, force: true });
    }
}

// ---------- Main flow tests (rate-limit disabled for speed). ----------

let server;
before(async () => {
    await ready();
    server = new Server();
    await server.ready();
});
after(async () => { await server.stop(); });

// Resolve a fresh captcha + nonce for every create. Difficulty is set low
// enough in the test config that the search completes in a few ms.
async function getPow() {
    const cap = await (await fetch(server.base + '/api/captcha')).json();
    const nonce = await solvePow(cap.token, cap.difficulty);
    return { token: cap.token, nonce };
}

async function postPaste(wire, { pow }) {
    return fetch(server.base + '/api/pastes', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/octet-stream',
            'X-Pow-Token': pow.token,
            'X-Pow-Nonce': pow.nonce
        },
        body: wire
    });
}

// One full create→open→fetch round trip on a plain-text paste.
async function createTextPaste({ body, password = '', burn = false }) {
    const seed = randomSeed();
    const key  = await deriveKey(seed, password);
    const payload   = packPayload({ format: FORMAT.TEXT, text: body });
    const envelope  = await sealEnvelope(payload, key);
    const challenge = await makeChallenge(key, { burn });
    const wire      = buildCreateBody(challenge, envelope);

    const pow = await getPow();
    const res = await postPaste(wire, { pow });
    assert.equal(res.status, 201, 'create returned ' + res.status);
    const { id, expires_at, ttl_seconds, size, burn: burnEcho } = await res.json();
    assert.equal(id.length, 8);
    assert.equal(burnEcho, burn);
    return { id, seed, key, password, expectedBody: body, expires_at, ttl_seconds, size };
}

async function openAndDecrypt({ id, seed, password = '' }) {
    const key = await deriveKey(seed, password);
    const openRes = await fetch(server.base + `/api/pastes/${id}/open`, { method: 'POST' });
    assert.equal(openRes.status, 200);
    const open = await openRes.json();
    const nonce = await fromB64(open.challenge.nonce);
    const ct    = await fromB64(open.challenge.ciphertext);
    const plaintext = await solveChallenge(nonce, ct, key);
    const blobRes = await fetch(server.base + `/api/pastes/${id}/blob`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: open.token, plaintext: await toB64(plaintext) })
    });
    return { open, blobRes, key };
}

test('GET /api/config returns expected fields', async () => {
    const cfg = await (await fetch(server.base + '/api/config')).json();
    assert.equal(cfg.app_name, 'TestBin');
    assert.equal(cfg.max_paste_bytes, 1048576);
    assert.equal(cfg.min_ttl_seconds, 60);
    assert.equal(cfg.max_ttl_seconds, 3600);
});

test('round trip: text paste, no password, no burn', async () => {
    const created = await createTextPaste({ body: 'hello cryptoblin 🐙' });
    // Server-side TTL formula: tiny paste should sit near max_ttl.
    assert.ok(created.ttl_seconds > 3500, 'expected ~max ttl, got ' + created.ttl_seconds);

    const { blobRes, key } = await openAndDecrypt(created);
    assert.equal(blobRes.status, 200);
    assert.equal(blobRes.headers.get('X-Burned'), '0');
    assert.equal(blobRes.headers.get('X-View-Count'), '1');
    assert.equal(parseInt(blobRes.headers.get('Content-Length'), 10), created.size);

    const envelope  = new Uint8Array(await blobRes.arrayBuffer());
    const plaintext = await openEnvelope(envelope, key);
    const payload   = unpackPayload(plaintext);
    assert.equal(payload.format, FORMAT.TEXT);
    assert.equal(payload.text, 'hello cryptoblin 🐙');
    assert.equal(payload.file, null);
});

test('view count increments across reads', async () => {
    const created = await createTextPaste({ body: 'view-counter' });
    const r1 = await openAndDecrypt(created);
    const r2 = await openAndDecrypt(created);
    const r3 = await openAndDecrypt(created);
    assert.equal(r1.blobRes.headers.get('X-View-Count'), '1');
    assert.equal(r2.blobRes.headers.get('X-View-Count'), '2');
    assert.equal(r3.blobRes.headers.get('X-View-Count'), '3');
});

test('password gate: wrong password yields bad_key, right password recovers', async () => {
    const created = await createTextPaste({ body: 'secret', password: 'correct' });

    // Wrong password — challenge decryption fails locally, but the test
    // helper still pushes its (garbage) plaintext to the server, which
    // collapses to 403 bad_key.
    const wrongKey = await deriveKey(created.seed, 'wrong');
    const openRes = await fetch(server.base + `/api/pastes/${created.id}/open`, { method: 'POST' });
    const open = await openRes.json();

    let solved;
    try {
        solved = await solveChallenge(
            await fromB64(open.challenge.nonce),
            await fromB64(open.challenge.ciphertext),
            wrongKey
        );
        assert.fail('challenge decrypt should have thrown');
    } catch { /* expected */ }
    void solved;

    // The wrong-key flow on the server: send arbitrary 33 bytes — must 403.
    const fake = new Uint8Array(33);
    const blobRes = await fetch(server.base + `/api/pastes/${created.id}/blob`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: open.token, plaintext: await toB64(fake) })
    });
    assert.equal(blobRes.status, 403);
    const errJson = await blobRes.json();
    assert.equal(errJson.error_code, 'bad_key');

    // Now with the correct password it must succeed.
    const ok = await openAndDecrypt({ ...created, password: 'correct' });
    assert.equal(ok.blobRes.status, 200);
});

test('decoy: unknown id returns same shape and rejects unlock', async () => {
    const fakeId = 'ZZZZ' + 'aaaa';   // 8 alphanumeric, almost certainly absent
    const openRes = await fetch(server.base + `/api/pastes/${fakeId}/open`, { method: 'POST' });
    assert.equal(openRes.status, 200);
    const open = await openRes.json();
    assert.ok(open.token && open.challenge?.nonce && open.challenge?.ciphertext);
    assert.equal(open.meta, undefined, '/open must not leak any meta');

    const fake = new Uint8Array(33);
    const blobRes = await fetch(server.base + `/api/pastes/${fakeId}/blob`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: open.token, plaintext: await toB64(fake) })
    });
    assert.equal(blobRes.status, 403);
    assert.equal((await blobRes.json()).error_code, 'bad_key');
});

test('challenge token is single-use', async () => {
    const created = await createTextPaste({ body: 'single-use' });
    const key = created.key;
    const openRes = await fetch(server.base + `/api/pastes/${created.id}/open`, { method: 'POST' });
    const open = await openRes.json();
    const plaintext = await solveChallenge(
        await fromB64(open.challenge.nonce),
        await fromB64(open.challenge.ciphertext),
        key
    );
    const ptB64 = await toB64(plaintext);

    const r1 = await fetch(server.base + `/api/pastes/${created.id}/blob`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: open.token, plaintext: ptB64 })
    });
    assert.equal(r1.status, 200);

    // Same token replayed -> 403 (server consumed the session entry).
    const r2 = await fetch(server.base + `/api/pastes/${created.id}/blob`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: open.token, plaintext: ptB64 })
    });
    assert.equal(r2.status, 403);
});

test('burn-after-read deletes the paste', async () => {
    const created = await createTextPaste({ body: 'flash paper', burn: true });

    const openRes1 = await fetch(server.base + `/api/pastes/${created.id}/open`, { method: 'POST' });
    const open1 = await openRes1.json();

    const plaintext = await solveChallenge(
        await fromB64(open1.challenge.nonce),
        await fromB64(open1.challenge.ciphertext),
        created.key
    );
    // Burn flag is end-to-end inside the AEAD plaintext.
    assert.equal(plaintext[32], 1, 'decrypted challenge must carry burn=1');

    const blobRes = await fetch(server.base + `/api/pastes/${created.id}/blob`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: open1.token, plaintext: await toB64(plaintext) })
    });
    assert.equal(blobRes.status, 200);
    assert.equal(blobRes.headers.get('X-Burned'), '1');

    // Second /open returns a decoy challenge (the row is gone); the blob
    // fetch with garbage plaintext must 403 — same as a fully unknown id.
    const openRes2 = await fetch(server.base + `/api/pastes/${created.id}/open`, { method: 'POST' });
    assert.equal(openRes2.status, 200);
    const open2 = await openRes2.json();
    const blobRes2 = await fetch(server.base + `/api/pastes/${created.id}/blob`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: open2.token, plaintext: await toB64(new Uint8Array(33)) })
    });
    assert.equal(blobRes2.status, 403);
});

test('size limit: too-large payload returns 413', async () => {
    const seed = randomSeed();
    const key  = await deriveKey(seed, '');
    const big  = new Uint8Array(2 * 1024 * 1024);
    big.fill(0x41);
    const payload   = packPayload({
        format: FORMAT.TEXT,
        file: { name: 'a.bin', mime: 'application/octet-stream', body: big }
    });
    const envelope  = await sealEnvelope(payload, key);
    const challenge = await makeChallenge(key);
    const wire      = buildCreateBody(challenge, envelope);
    const pow = await getPow();
    const res = await postPaste(wire, { pow });
    assert.equal(res.status, 413);
});

test('PoW gate: missing headers reject create', async () => {
    const seed = randomSeed();
    const key  = await deriveKey(seed, '');
    const env  = await sealEnvelope(packPayload({ format: FORMAT.TEXT, text: 'x' }), key);
    const ch   = await makeChallenge(key);
    const wire = buildCreateBody(ch, env);
    const res = await fetch(server.base + '/api/pastes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: wire
    });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error_code, 'pow_required');
});

test('PoW gate: bad signature rejected', async () => {
    const seed = randomSeed();
    const key  = await deriveKey(seed, '');
    const env  = await sealEnvelope(packPayload({ format: FORMAT.TEXT, text: 'x' }), key);
    const ch   = await makeChallenge(key);
    const wire = buildCreateBody(ch, env);
    const res = await postPaste(wire, {
        pow: { token: 'AAAA.1.1.AAAA', nonce: '0' }
    });
    assert.equal(res.status, 403);
    const code = (await res.json()).error_code;
    assert.ok(code === 'pow_invalid' || code === 'pow_expired',
        'unexpected ' + code);
});

test('PoW gate: each captcha is single-use', async () => {
    const seed = randomSeed();
    const key  = await deriveKey(seed, '');
    const env  = await sealEnvelope(packPayload({ format: FORMAT.TEXT, text: 'x' }), key);
    const ch   = await makeChallenge(key);
    const wire = buildCreateBody(ch, env);
    const pow  = await getPow();
    const r1 = await postPaste(wire, { pow });
    assert.equal(r1.status, 201);
    // Same token+nonce again — replay set must reject.
    const env2 = await sealEnvelope(packPayload({ format: FORMAT.TEXT, text: 'y' }), key);
    const ch2  = await makeChallenge(key);
    const wire2 = buildCreateBody(ch2, env2);
    const r2 = await postPaste(wire2, { pow });
    assert.equal(r2.status, 403);
    assert.equal((await r2.json()).error_code, 'pow_replayed');
});

test('reads are not rate-limited', async () => {
    // Stand up a separate instance with rate-limit=2s. Read endpoints must
    // work back-to-back regardless. Captcha (the only rate-gated endpoint)
    // would 429 on a tight loop; reads must not.
    const rl = new Server({ rateLimitSeconds: 2, powDifficulty: 6 });
    try {
        await rl.ready();
        // Use the live `server` for the create, then only hit `rl` for reads.
        // Simpler: just create on `rl` once, then read repeatedly.
        const seed = randomSeed();
        const key  = await deriveKey(seed, '');
        const env  = await sealEnvelope(packPayload({ format: FORMAT.TEXT, text: 'reads' }), key);
        const ch   = await makeChallenge(key);
        const wire = buildCreateBody(ch, env);
        const cap  = await (await fetch(rl.base + '/api/captcha')).json();
        const nonce = await solvePow(cap.token, cap.difficulty);
        const created = await fetch(rl.base + '/api/pastes', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/octet-stream',
                'X-Pow-Token': cap.token,
                'X-Pow-Nonce': nonce
            },
            body: wire
        });
        assert.equal(created.status, 201);
        const { id } = await created.json();

        // Hammer /open back-to-back. None must 429.
        for (let i = 0; i < 5; ++i) {
            const r = await fetch(rl.base + `/api/pastes/${id}/open`, { method: 'POST' });
            assert.equal(r.status, 200, 'open #' + i + ' was ' + r.status);
        }
    } finally {
        await rl.stop();
    }
});

test('invalid id format returns 400', async () => {
    const r = await fetch(server.base + '/api/pastes/short/open', { method: 'POST' });
    assert.equal(r.status, 400);
});

test('TTL formula: large paste lives near min_ttl', async () => {
    // ~512 KB → halfway to max_paste_bytes (1 MB) → ~midway between min and max.
    const half = new Uint8Array(512 * 1024);
    half.fill(0x42);
    const seed = randomSeed();
    const key  = await deriveKey(seed, '');
    const payload   = packPayload({
        format: FORMAT.TEXT,
        file: { name: 'b.bin', mime: 'application/octet-stream', body: half }
    });
    const envelope  = await sealEnvelope(payload, key);
    const challenge = await makeChallenge(key);
    const wire      = buildCreateBody(challenge, envelope);
    const pow = await getPow();
    const res = await postPaste(wire, { pow });
    assert.equal(res.status, 201);
    const j = await res.json();
    // Exponential decay (k=5): ratio≈0.5 → frac≈0.076 → ttl ≈ min + span*0.076.
    // With min=60, max=3600 → ~330s. Allow a generous window.
    assert.ok(j.ttl_seconds >= 200 && j.ttl_seconds <= 500,
        'unexpected ttl ' + j.ttl_seconds);
});

// ---------- Rate-limit isolation: needs its own server with rl=2s. ----------

test('rate limit gates the captcha endpoint', async () => {
    // The rate limiter sits in front of /api/captcha, so two captcha
    // requests in a row from the same IP must produce one 200 and one 429.
    const rl = new Server({ rateLimitSeconds: 2 });
    try {
        await rl.ready();
        const r1 = await fetch(rl.base + '/api/captcha');
        const r2 = await fetch(rl.base + '/api/captcha');
        assert.equal(r1.status, 200);
        assert.equal(r2.status, 429);
        assert.equal((await r2.json()).error_code, 'rate_limited');
    } finally {
        await rl.stop();
    }
});
