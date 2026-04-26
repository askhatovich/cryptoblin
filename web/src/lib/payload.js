// Plaintext envelope inside the AEAD-sealed blob.
//
//   [1 byte format]                     // 0=plain, 1=markdown, 2=code
//   [u16 BE langLen][lang utf-8]        // empty unless format=code
//   [u32 BE textLen][text utf-8]        // optional (may be 0)
//   [u16 BE nameLen][file name utf-8]   // optional
//   [u16 BE mimeLen][file mime utf-8]
//   [u32 BE fileLen][file body bytes]
//
// A note must carry text or a file (or both). The server never sees this
// layout — it is wrapped end-to-end by sealEnvelope().

export const FORMAT = { TEXT: 0, MARKDOWN: 1, CODE: 2 };
export const FORMAT_NAME = { 0: 'text', 1: 'markdown', 2: 'code' };

const ENC = new TextEncoder();
const DEC = new TextDecoder();

// Wire-layout field sizes. Pulled out as constants so the size of the
// fixed-overhead header (`PAYLOAD_HEADER_BYTES`) is computed from the same
// numbers the encoder/decoder use, instead of repeating raw 1/2/4s.
const FORMAT_BYTE_BYTES   = 1;       // single-byte format selector
const SHORT_LEN_BYTES     = 2;       // u16 BE length prefix (lang/name/mime)
const LONG_LEN_BYTES      = 4;       // u32 BE length prefix (text/file body)

// Size of every byte that does NOT belong to user data — i.e. what the
// envelope costs even when text and file are empty.
export const PAYLOAD_HEADER_BYTES =
      FORMAT_BYTE_BYTES
    + SHORT_LEN_BYTES         // langLen
    + LONG_LEN_BYTES          // textLen
    + SHORT_LEN_BYTES         // nameLen
    + SHORT_LEN_BYTES         // mimeLen
    + LONG_LEN_BYTES;         // fileLen

export function packPayload({ format = FORMAT.TEXT, lang = '', text = '', file = null }) {
    const langB = ENC.encode(lang || '');
    const textB = typeof text === 'string' ? ENC.encode(text)
                : (text instanceof Uint8Array ? text : new Uint8Array(0));
    const nameB = ENC.encode(file?.name || '');
    const mimeB = ENC.encode(file?.mime || '');
    const fileB = file?.body instanceof Uint8Array ? file.body : new Uint8Array(0);

    const total = PAYLOAD_HEADER_BYTES
        + langB.length + textB.length
        + nameB.length + mimeB.length + fileB.length;

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
    if (bytes.length < PAYLOAD_HEADER_BYTES) throw new Error('payload_too_short');
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let o = 0;
    const format = bytes[o]; o += FORMAT_BYTE_BYTES;

    const langLen = view.getUint16(o, false); o += SHORT_LEN_BYTES;
    if (o + langLen > bytes.length) throw new Error('payload_corrupt');
    const lang = DEC.decode(bytes.subarray(o, o + langLen)); o += langLen;

    const textLen = view.getUint32(o, false); o += LONG_LEN_BYTES;
    if (o + textLen > bytes.length) throw new Error('payload_corrupt');
    const text = DEC.decode(bytes.subarray(o, o + textLen)); o += textLen;

    const nameLen = view.getUint16(o, false); o += SHORT_LEN_BYTES;
    if (o + nameLen > bytes.length) throw new Error('payload_corrupt');
    const name = DEC.decode(bytes.subarray(o, o + nameLen)); o += nameLen;

    const mimeLen = view.getUint16(o, false); o += SHORT_LEN_BYTES;
    if (o + mimeLen > bytes.length) throw new Error('payload_corrupt');
    const mime = DEC.decode(bytes.subarray(o, o + mimeLen)); o += mimeLen;

    const fileLen = view.getUint32(o, false); o += LONG_LEN_BYTES;
    if (o + fileLen > bytes.length) throw new Error('payload_corrupt');
    const fileBody = bytes.subarray(o, o + fileLen);

    const hasFile = nameLen > 0 || mimeLen > 0 || fileLen > 0;
    return {
        format,
        lang,
        text,
        file: hasFile ? { name, mime, body: new Uint8Array(fileBody) } : null
    };
}

// Common-language → file-extension map for "Save text as file" / "Show raw".
// Anything not in the map falls back to .txt.
export const CODE_EXT = {
    bash: 'sh', c: 'c', cpp: 'cpp', cmake: 'cmake', css: 'css',
    diff: 'diff', dockerfile: 'Dockerfile', go: 'go', html: 'html',
    ini: 'ini', java: 'java', javascript: 'js', json: 'json',
    kotlin: 'kt', lua: 'lua', makefile: 'mk', markdown: 'md',
    nginx: 'conf', objectivec: 'm', perl: 'pl', php: 'php',
    plaintext: 'txt', python: 'py', ruby: 'rb', rust: 'rs',
    scss: 'scss', shell: 'sh', sql: 'sql', swift: 'swift',
    toml: 'toml', typescript: 'ts', xml: 'xml', yaml: 'yml'
};

export function suggestedTextFilename(format, lang) {
    if (format === FORMAT.MARKDOWN) return 'note.md';
    if (format === FORMAT.CODE) {
        const ext = CODE_EXT[(lang || '').toLowerCase()] || 'txt';
        return 'snippet.' + ext;
    }
    return 'note.txt';
}
