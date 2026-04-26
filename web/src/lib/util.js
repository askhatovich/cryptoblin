export function formatBytes(n) {
    if (n < 1024) return n + ' B';
    const units = ['KB', 'MB', 'GB'];
    let i = -1;
    let v = n;
    do { v /= 1024; ++i; } while (v >= 1024 && i < units.length - 1);
    return v.toFixed(v < 10 ? 1 : 0) + ' ' + units[i];
}

// Localised duration formatter. Picks the largest sensible unit. Plural
// helper avoids needing a real ICU library — every locale defines a small
// set of *_one / *_few / *_many keys that we map below.
export function formatDuration(seconds, t) {
    if (seconds < 0) seconds = 0;
    const s = Math.floor(seconds);
    if (s < 60) return pluralUnit(s, 'second', t);
    const m = Math.floor(s / 60);
    if (m < 60) return pluralUnit(m, 'minute', t);
    const h = Math.floor(m / 60);
    if (h < 48) return pluralUnit(h, 'hour', t);
    const d = Math.floor(h / 24);
    return pluralUnit(d, 'day', t);
}

// Picks _one for n=1 and the language's _many otherwise. Russian also uses
// _few for n in {2,3,4} (not 12,13,14) — encoded inline rather than pulling
// in Intl.PluralRules so the bundle stays small.
function pluralUnit(n, base, t) {
    const lang = (navigator.language || 'en').slice(0, 2).toLowerCase();
    let form = 'many';
    if (n % 10 === 1 && n % 100 !== 11) form = 'one';
    else if (lang === 'ru' && [2, 3, 4].includes(n % 10) && ![12, 13, 14].includes(n % 100)) form = 'few';
    const key = `units.${base}_${form}`;
    return `${n} ${t(key)}`;
}

export function downloadBytes(bytes, filename, mime) {
    const blob = new Blob([bytes], { type: mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || 'paste.bin';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

export async function copyText(s) {
    // Async clipboard API needs a secure context (https or localhost). On
    // plain http it is undefined, so we fall through to the legacy path.
    if (navigator.clipboard && navigator.clipboard.writeText) {
        try { await navigator.clipboard.writeText(s); return; }
        catch { /* fall through to execCommand */ }
    }
    const ta = document.createElement('textarea');
    ta.value = s;
    ta.setAttribute('readonly', '');
    ta.style.position = 'absolute';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    finally { ta.remove(); }
    if (!ok) throw new Error('copy_failed');
}
