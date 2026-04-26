// REST helpers. Errors throw with `code` and `status` properties.

async function jsonOrThrow(res) {
    let data = null;
    try { data = await res.json(); } catch { /* may be empty */ }
    if (!res.ok) {
        const err = new Error(data?.error_code || `http_${res.status}`);
        err.code = data?.error_code || `http_${res.status}`;
        err.status = res.status;
        throw err;
    }
    return data;
}

function throwIfNotOk(res, data) {
    if (!res.ok) {
        const err = new Error(data?.error_code || `http_${res.status}`);
        err.code = data?.error_code || `http_${res.status}`;
        err.status = res.status;
        throw err;
    }
}

export const api = {
    async getConfig() {
        const res = await fetch('/api/config');
        return jsonOrThrow(res);
    },

    async getCaptcha() {
        const res = await fetch('/api/captcha');
        return jsonOrThrow(res);
    },

    // body = [33-byte plaintext | 24-byte nonce | 49-byte cipher | blob bytes]
    // Burn flag is byte 32 of the plaintext.
    async createPaste(body, { powToken, powNonce }) {
        const res = await fetch('/api/pastes', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/octet-stream',
                'X-Pow-Token': powToken,
                'X-Pow-Nonce': powNonce
            },
            body
        });
        return jsonOrThrow(res);
    },

    async deletePaste(id, token) {
        const res = await fetch(`/api/pastes/${encodeURIComponent(id)}`, {
            method: 'DELETE',
            headers: { 'X-Delete-Token': token }
        });
        return jsonOrThrow(res);
    },

    async openPaste(id) {
        const res = await fetch(`/api/pastes/${encodeURIComponent(id)}/open`, {
            method: 'POST'
        });
        return jsonOrThrow(res);
    },

    // Streams the blob and reports progress as bytes arrive. Returns the
    // full Uint8Array plus the X-View-Count / X-Burned headers.
    async fetchBlob(id, token, plaintextB64, onProgress) {
        const res = await fetch(`/api/pastes/${encodeURIComponent(id)}/blob`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, plaintext: plaintextB64 })
        });
        if (!res.ok) {
            let data = null;
            try { data = await res.json(); } catch { /* binary 200 only */ }
            throwIfNotOk(res, data);
        }
        const total     = parseInt(res.headers.get('Content-Length') || '0', 10) || 0;
        const burned    = res.headers.get('X-Burned') === '1';
        const views     = parseInt(res.headers.get('X-View-Count') || '0', 10) || 0;
        const createdAt = parseInt(res.headers.get('X-Created-At') || '0', 10) || 0;
        const expiresAt = parseInt(res.headers.get('X-Expires-At') || '0', 10) || 0;

        if (!res.body || !res.body.getReader) {
            const buf = new Uint8Array(await res.arrayBuffer());
            if (onProgress) onProgress(buf.length, buf.length);
            return { bytes: buf, burned, views, createdAt, expiresAt, size: buf.length };
        }
        const reader = res.body.getReader();
        const chunks = [];
        let received = 0;
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
            received += value.length;
            if (onProgress) onProgress(received, total || received);
        }
        const out = new Uint8Array(received);
        let off = 0;
        for (const c of chunks) { out.set(c, off); off += c.length; }
        return { bytes: out, burned, views, createdAt, expiresAt, size: out.length };
    }
};
