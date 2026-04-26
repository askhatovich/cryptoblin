# cryptoblin

Self-hosted, zero-knowledge note and file sharing.

The server stores ciphertext and never sees the encryption key, the password,
or the plaintext. All cryptography happens in the sender's browser (or in the
`blin` CLI); the server's job is to hand the ciphertext back to whoever can
prove they hold the right key.

The name is a shortening of **Crypto Blob Insert**, doubling as the Russian
word **блин** ("blin", a thin pancake) — quick, light, eaten in one go.

Inspired by [PrivateBin](https://github.com/PrivateBin/PrivateBin); cryptoblin
is a modern descendant aimed at simplicity, performance, and noticeably better
handling of large file attachments.

---

## Features

- Pure zero-knowledge: server stores only ciphertext + a tamper-evident
  proof-of-key challenge.
- XChaCha20-Poly1305 AEAD with Argon2id-derived keys.
- Optional password (separate KDF input).
- Burn-after-read: paste self-destructs on first successful open, atomically.
- Owner-only delete via a one-shot capability token.
- Size-aware exponential TTL: small notes live the maximum time, large blobs
  expire fast.
- Decoy responses: opening a non-existent paste id returns the same shape as a
  real one, so id existence is not probeable.
- Single-file C++ server (Crow + SQLite + libsodium-on-the-client) with the
  full SPA bundled into the binary at compile time.
- Cross-platform CLI (`blin`) for Linux and Windows, statically linkable.

---

## Architecture

```
                        ┌────────────────────────┐
   ┌─────────┐  https   │     cryptoblin (C++)   │
   │ browser │◀────────▶│  Crow router           │
   └────┬────┘          │  ┌──────────────────┐  │     ┌──────────────┐
        │ libsodium     │  │ SQLite metadata  │  │     │ blob files   │
        ▼ (WASM, in JS) │  └──────────────────┘  │     │ (one per id) │
   plaintext / file     │  ┌──────────────────┐  │     └──────────────┘
        │               │  │ in-memory:       │  │             ▲
        ▼ AEAD          │  │  rate-limit, PoW │  │             │
   ciphertext ──────────▶  │  replay set,     │──┼─────────────┘
                        │  │  /open sessions  │  │
                        │  └──────────────────┘  │
                        └────────────────────────┘

   key  =  Argon2id(seed + ":" + password,
                    salt = blake2b("cryptoblin/v1/" + seed))
   key  lives only in the URL fragment (#…), never sent to the server.
```

### Wire format

A paste created via `POST /api/pastes` is a single binary stream:

```
[ 33 bytes challenge plaintext ] [32 random | 1 byte burn flag]
[ 24 bytes challenge nonce     ]
[ 49 bytes challenge ciphertext] (AEAD over the plaintext, 16-byte tag)
[  N bytes envelope            ] [1 ver | 24 nonce | ct + 16 mac]
```

The envelope wraps the user payload:

```
[ 1 byte format ] (0 = text, 1 = markdown, 2 = code)
[ u16 langLen   ][ utf-8 lang   ]
[ u32 textLen   ][ utf-8 text   ]
[ u16 nameLen   ][ utf-8 file name ]
[ u16 mimeLen   ][ utf-8 file mime ]
[ u32 fileLen   ][ raw file bytes  ]
```

The 33rd plaintext byte ("burn") is committed at create time and
AEAD-authenticated end to end: the server reads it once in cleartext to
populate its DB row, and a recipient who decrypts the challenge sees exactly
the bit the creator set.

### URL fragments

Routing is entirely client-side. The path is always `/`; the rest lives in
the fragment, which browsers do not transmit:

```
/#<id>:<seed>          →  view, no password
/#<id>:<seed>:p        →  view, prompts for password
/#del:<id>:<token>     →  owner-only delete (printed once at create time)
```

`id` is 8 alphanumeric characters; `seed` is 8 base62 characters; `token` is
16 random bytes, base64-encoded.

### Lifetime formula

TTL is exponentially-anchored decay between min and max:

```
ratio = (size − 1 KiB) / (max_paste_bytes − 1 KiB)
ttl   = min_ttl + (max_ttl − min_ttl) · (e^(−5·ratio) − e^−5) / (1 − e^−5)
```

The result: small notes sit at the ceiling for almost the whole curve, and
the cliff to `min_ttl` is concentrated near the cap. With defaults of
30 days / 1 hour over a 100 MiB cap:

| size       | TTL          |
|------------|--------------|
| ≤ 1 KiB    | 30 days      |
| 10 MiB     | ~ 18 days    |
| 50 MiB     | ~ 2.3 days   |
| 90 MiB     | ~ 4.2 hours  |
| 100 MiB    | 1 hour       |

---

## API

All endpoints are JSON unless noted. Errors are
`{ "error_code": "<code>", "message": "<optional>" }` with a 4xx/5xx status.

| Method | Path                          | Purpose                                          |
|--------|-------------------------------|--------------------------------------------------|
| `GET`  | `/api/config`                 | App name/title, version, paste-byte / TTL limits |
| `GET`  | `/api/captcha`                | Issue a fresh signed PoW token                   |
| `POST` | `/api/pastes`                 | Create a paste (raw octet-stream body)           |
| `POST` | `/api/pastes/{id}/open`       | Get challenge `nonce`+`ciphertext` to decrypt    |
| `POST` | `/api/pastes/{id}/blob`       | Submit decrypted plaintext, stream the blob      |
| `DELETE`| `/api/pastes/{id}`           | Owner delete (`X-Delete-Token` header required)  |

### Create flow

1. Client fetches `/api/captcha` → `{ token, difficulty }`.
2. Client brute-forces a nonce so `leading_zero_bits(SHA-256(token + ":" + nonce)) ≥ difficulty`.
3. Client builds the wire format, POSTs to `/api/pastes` with headers
   `X-Pow-Token` / `X-Pow-Nonce`. Server re-verifies and consumes the token
   (one-shot replay set), reads the burn bit from plaintext byte 32, writes
   the row and the blob file.
4. Server returns `{ id, expires_at, size, ttl_seconds, burn, delete_token }`.

### Open flow

1. `POST /api/pastes/{id}/open` → `{ token, challenge: { nonce, ciphertext } }`.
   Non-existent ids get a synthetic decoy with random bytes of the same shape.
   No metadata is leaked at this stage.
2. Client decrypts the challenge under its key, extracts the proof plaintext
   (and the burn flag — used to render a "this will be destroyed" warning
   *before* the blob is fetched).
3. `POST /api/pastes/{id}/blob` with `{ token, plaintext: <b64> }`. Server
   constant-time-compares against the stored plaintext. On match the blob
   bytes are streamed back; on burn=true the row is atomically deleted before
   the body is sent. View count and burned flag come back as response headers.

### Delete flow

`DELETE /api/pastes/{id}` with `X-Delete-Token: <b64>`. The server stores
SHA-256(token); a constant-time compare and `DELETE` happen inside a single
DB call. Missing token, wrong token, missing id all collapse to
`403 bad_token` with no distinguishable timing.

---

## Threat model

cryptoblin is designed to keep specific attackers out of specific data. It is
not magic; the limits below matter.

### What is mitigated

- **Honest-but-curious server operator.** The server holds ciphertext, a
  random salt, an opaque AEAD challenge, and a SHA-256 of the delete token.
  Reading the disk yields no plaintext. There is no key escrow.
- **Database / disk theft.** Same as above — a stolen DB or backup leaks
  paste sizes and timestamps but no contents.
- **TLS terminator / reverse proxy.** Same — the encryption key never appears
  in any HTTP payload. It lives only in the URL fragment, which browsers
  never transmit.
- **Network passive attacker.** Cipher is XChaCha20-Poly1305; passwords go
  through Argon2id with `OPSLIMIT_INTERACTIVE` / `MEMLIMIT_INTERACTIVE`.
  Without HTTPS the attacker still cannot read content; with HTTPS they also
  cannot see ids or sizes.
- **Server-side ciphertext tampering.** AEAD authenticates the envelope. The
  burn flag specifically is committed inside the AEAD plaintext, so the
  server cannot silently flip burn=false → burn=true (or vice versa) on
  pastes it cannot decrypt.
- **Existence probing.** `/api/pastes/{id}/open` returns the same JSON shape
  for real and missing ids. `/blob` collapses every failure mode to
  `403 bad_key`. Decoy challenges are uniform-random.
- **Burn race.** Burn-after-read is implemented as an atomic `DELETE … WHERE
  id = ?`; only one `/blob` call wins the row, the rest get `bad_key`.
- **Captcha replay & abuse.** PoW token is HMAC-signed, single-use, and TTLed.
  Captcha issuance is per-IP rate-limited so a malicious client cannot
  exhaust the replay set.
- **Accidental burn.** The CLI/web client decrypts the burn flag *before*
  calling `/blob`; if it is set, the user is shown a confirmation that the
  paste will be destroyed on continue.

### What is NOT mitigated

- **Compromised endpoint.** A keylogger, malicious browser extension, or
  modified `blin` binary on either side defeats the model trivially. Verify
  releases (signed tarballs, reproducible-ish builds via the GitHub CI).
- **Active in-flight attacker without HTTPS.** A MITM that can rewrite the
  served HTML can substitute a bundle that exfiltrates the URL fragment.
  Use HTTPS in production.
- **Brute-force against weak passwords.** Argon2id is tuned for interactive
  costs; a 4-character password can still be enumerated. Use real passwords
  or rely on the URL key alone.
- **Log/replay of the URL.** Anyone who sees the full URL (including the
  fragment) can read the paste until TTL or burn. Treat URLs as secrets.
- **Anonymity / metadata.** The server logs IPs by default for rate limiting
  and PoW issuance. cryptoblin is about content secrecy, not anonymity. Pair
  with Tor / a proxy if anonymity matters.
- **Denial of service.** PoW + per-IP rate limit + size cap raise the cost
  of bulk creation, but a determined attacker with many IPs can still flood
  reads or fill the cap. Run behind a normal HTTP frontend (nginx/caddy) for
  layer-7 limits if you expect abuse.

---

## Building

### Server (Debian 12+ / Ubuntu LTS)

```sh
sudo apt install build-essential cmake pkg-config \
                 libsqlite3-dev libsodium-dev libmbedtls-dev \
                 nodejs npm

cd web && npm ci && npm run build && bash embed.sh && cd ..
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/src/cryptoblin --config /etc/cryptoblin.ini
```

`cmake --install build` drops `cryptoblin` and `blin` into the prefix.

### CLI only (`blin`)

```sh
cmake -B build -DBUILD_SERVER=OFF -DBUILD_CLI=ON
cmake --build build -j
```

### Windows CLI

The CI builds a static-ish `blin.exe` via vcpkg. Local reproduction:

```pwsh
vcpkg install libsodium:x64-windows-static-md mbedtls:x64-windows-static-md
cmake -B build -DBUILD_SERVER=OFF -DBUILD_CLI=ON `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static-md
cmake --build build --config Release -j
```

---

## Configuration (`config.ini`)

```ini
[server]
log_level    = info
bind_address = 0.0.0.0
bind_port    = 8080
app_name     = CryptoBlin
title        =                 # optional override for the header / <title>

[storage]
db_path  = /var/lib/cryptoblin/cryptoblin.sqlite
blob_dir = /var/lib/cryptoblin/blobs

[retention]
max_paste_bytes = 104857600    # 100 MiB
min_ttl_seconds = 3600
max_ttl_seconds = 2592000

[limits]
rate_limit_per_ip_seconds = 3
total_pastes_cap          = 0  # 0 = unlimited

[captcha]
difficulty_bits = 18
ttl_seconds     = 300
```

---

## CLI

```sh
echo "secret" | blin send                        # text from stdin
blin send -b README.md                            # burn-after-read, file only
echo "see attached" | blin send report.pdf       # text + attachment
blin get https://paste.dotcpp.ru/#abcd1234:wxyz5678
blin delete https://paste.dotcpp.ru/#del:abcd1234:AAA…
```

Server URL is read from `$HOME/.config/askhatovich/cryptoblin/config.conf`
(format: `SERVER=https://example.com`); default is `https://paste.dotcpp.ru`.

`blin --help` documents every flag and the stdout/stderr contract (data on
stdout, machine-parseable `key: value` records on stderr).

---

## Development

```sh
# server unit tests
ctest --test-dir build --output-on-failure

# end-to-end tests against a real running binary
cd web && node --test tests/
```

Releases are produced by GitHub Actions on `v*` tags: Linux tarballs for
Debian 12 and Debian 13 (server + CLI), and a Windows zip with `blin.exe`.
SHA-256 sums sit next to each artifact.

---

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
