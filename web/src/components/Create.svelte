<script>
    import { onMount } from 'svelte';
    import { t } from '../lib/i18n.js';
    import { api } from '../lib/api.js';
    import {
        generateKeySeed, deriveKey, makeChallenge, sealEnvelope,
        ENVELOPE_OVERHEAD_BYTES
    } from '../lib/crypto.js';
    import { solve as solvePow } from '../lib/pow.js';
    import { packPayload, FORMAT, PAYLOAD_HEADER_BYTES } from '../lib/payload.js';
    import { LANGUAGES } from '../lib/format.js';
    import { formatBytes, formatDuration, copyText } from '../lib/util.js';
    import { buildPasteUrl, buildDeleteUrl } from '../lib/urlfrag.js';
    import { popDraft } from '../lib/draft.js';
    import QrModal from './QrModal.svelte';

    let { serverConfig } = $props();

    let format = $state(FORMAT.TEXT);
    let body = $state('');
    let lang = $state('auto');
    let burn = $state(false);
    let password = $state('');
    let file = $state(null);   // { name, type, size, bytes? } – we only read bytes on submit

    let submitting = $state(false);
    let phase = $state('idle');
    let powTries = $state(0);
    let error = $state(null);
    let result = $state(null);
    let copied = $state(false);
    let copyError = $state(false);
    let showQr = $state(false);
    let dragging = $state(false);

    // "Create copy" hand-off from View — pre-fill the form once and clear.
    onMount(() => {
        const d = popDraft();
        if (d) {
            format   = d.format ?? FORMAT.TEXT;
            body     = d.text   ?? '';
            lang     = d.lang   ?? 'auto';
            if (d.file) {
                file = {
                    name: d.file.name,
                    type: d.file.mime,
                    size: d.file.body.length,
                    bytes: d.file.body          // already a Uint8Array
                };
            }
        }
    });

    // Bytes the wire format costs even when text and file are empty:
    // outer AEAD wrapping (version + nonce + MAC) plus the payload's
    // fixed-length header (format byte + length prefixes).
    const ENVELOPE_OVERHEAD_TOTAL = ENVELOPE_OVERHEAD_BYTES + PAYLOAD_HEADER_BYTES;
    let estimatedSize = $derived.by(() => {
        const textBytes = new TextEncoder().encode(body || '').length;
        const fileBytes = file?.size || 0;
        return ENVELOPE_OVERHEAD_TOTAL + textBytes + fileBytes;
    });
    let estimatedTtl = $derived.by(() => {
        if (!serverConfig) return 0;
        const max = serverConfig.max_ttl_seconds;
        const min = serverConfig.min_ttl_seconds;
        const cap = serverConfig.max_paste_bytes;
        const FLOOR = 1024;
        if (cap <= FLOOR || estimatedSize <= FLOOR) return max;
        const s = Math.min(estimatedSize, cap);
        const k = 5.0;
        const ratio = (s - FLOOR) / (cap - FLOOR);
        const frac  = (Math.exp(-k * ratio) - Math.exp(-k)) / (1 - Math.exp(-k));
        return min + (max - min) * frac;
    });
    let overLimit = $derived.by(() =>
        serverConfig && estimatedSize > serverConfig.max_paste_bytes);
    let nothingToSend = $derived.by(() =>
        (body || '').length === 0 && !file);

    function pickFile(e) {
        const f = e.target.files?.[0];
        if (f) file = f;
    }
    function clearFile() { file = null; }
    function onDrop(e) {
        e.preventDefault();
        dragging = false;
        const f = e.dataTransfer?.files?.[0];
        if (f) file = f;
    }

    async function readFileBytes(f) {
        // Note: don't test `f.bytes` truthiness — Blob.prototype.bytes() exists
        // as a method on every File in modern browsers, so it would shadow our
        // draft hand-off and return the function reference.
        if (f?.bytes instanceof Uint8Array) return f.bytes;   // "Create copy" draft
        return new Uint8Array(await f.arrayBuffer());
    }

    async function submit(e) {
        e?.preventDefault?.();
        if (submitting || overLimit || nothingToSend) return;
        error = null;
        submitting = true;
        powTries = 0;
        try {
            phase = 'captcha';
            const cap = await api.getCaptcha();

            phase = 'pow';
            const powNonce = await solvePow(cap.token, cap.difficulty, n => { powTries = n; });

            phase = 'encrypting';
            const seed = generateKeySeed();
            const key  = await deriveKey(seed, password || '');

            const filePart = file ? {
                name: file.name || 'file',
                mime: file.type || 'application/octet-stream',
                body: await readFileBytes(file)
            } : null;

            const payload = packPayload({
                format,
                lang: format === FORMAT.CODE ? (lang === 'auto' ? '' : lang) : '',
                text: body || '',
                file: filePart
            });

            const envelope  = await sealEnvelope(payload, key);
            const challenge = await makeChallenge(key, { burn });

            const total = new Uint8Array(
                challenge.plaintext.length +
                challenge.nonce.length +
                challenge.ciphertext.length +
                envelope.length
            );
            let off = 0;
            total.set(challenge.plaintext, off); off += challenge.plaintext.length;
            total.set(challenge.nonce, off);     off += challenge.nonce.length;
            total.set(challenge.ciphertext, off); off += challenge.ciphertext.length;
            total.set(envelope, off);

            phase = 'uploading';
            const created = await api.createPaste(total, {
                powToken: cap.token,
                powNonce
            });

            const hasPassword = !!password;
            const url = buildPasteUrl(created.id, seed, hasPassword);
            const deleteUrl = buildDeleteUrl(created.id, created.delete_token);
            result = {
                url,
                deleteUrl,
                expiresAt: created.expires_at,
                ttl: created.ttl_seconds,
                size: created.size,
                burn,
                hasPassword
            };
            body = ''; password = ''; file = null;
        } catch (e) {
            error = 'errors.' + (e.code || 'internal');
        } finally {
            submitting = false;
            phase = 'idle';
        }
    }

    async function copyLink() {
        if (!result) return;
        copyError = false;
        try {
            await copyText(result.url);
            copied = true;
            setTimeout(() => { copied = false; }, 1400);
        } catch {
            copyError = true;
            setTimeout(() => { copyError = false; }, 1800);
        }
    }

    function reset() { result = null; error = null; copied = false; showQr = false; }
</script>

{#if !result}
<form class="card" onsubmit={submit}>
    <div class="row" style="align-items: flex-end; gap: 12px; margin-bottom: 10px;">
        <div class="field" style="flex: 0 0 auto; margin-bottom: 0;">
            <label for="fmt">{$t('create.format')}</label>
            <select id="fmt" bind:value={format} style="width: auto; min-width: 160px;">
                <option value={FORMAT.TEXT}>{$t('create.format_text')}</option>
                <option value={FORMAT.MARKDOWN}>{$t('create.format_markdown')}</option>
                <option value={FORMAT.CODE}>{$t('create.format_code')}</option>
            </select>
        </div>
        {#if format === FORMAT.CODE}
            <div class="field" style="flex: 0 0 auto; margin-bottom: 0;">
                <label for="lang">{$t('create.language')}</label>
                <select id="lang" bind:value={lang} style="width: auto; min-width: 140px;">
                    {#each LANGUAGES as l}<option value={l}>{l}</option>{/each}
                </select>
            </div>
        {/if}
    </div>

    <div class="field">
        <textarea
            bind:value={body}
            placeholder={$t('create.body_placeholder')}
            spellcheck={format !== FORMAT.CODE}
        ></textarea>
    </div>

    <div class="field">
        <label
            class="dropzone compact"
            class:over={dragging}
            ondragover={(e) => { e.preventDefault(); dragging = true; }}
            ondragleave={() => dragging = false}
            ondrop={onDrop}
        >
            <input type="file" hidden onchange={pickFile} />
            {#if file}
                <div class="file-info">📎 {file.name}</div>
                <div class="dim">
                    {formatBytes(file.size)}
                    <button type="button" class="ghost"
                            style="margin-left: 8px; padding: 2px 8px; font-size: 12px;"
                            onclick={(e) => { e.preventDefault(); clearFile(); }}>
                        {$t('create.remove_file')}
                    </button>
                </div>
            {:else}
                <div>📎 {$t('create.attach_file')}</div>
            {/if}
        </label>
    </div>

    <div class="field">
        <label class="checkbox">
            <input type="checkbox" bind:checked={burn} />
            <span class="label-text">
                <span class="opt-title">{$t('create.burn')}</span>
                <div class="hint">{$t('create.burn_hint')}</div>
            </span>
        </label>
    </div>

    <div class="field">
        <label for="pw" class="strong">{$t('create.password')}</label>
        <input id="pw" type="password" autocomplete="new-password"
               placeholder={$t('create.password_placeholder')}
               bind:value={password} />
        <div class="hint">{$t('create.password_hint')}</div>
    </div>

    {#if serverConfig}
        <div class="hint" style="margin-bottom: 10px;">
            {$t('create.size_used', {
                size: formatBytes(estimatedSize),
                limit: formatBytes(serverConfig.max_paste_bytes)
            })}
            — {$t('create.ttl_estimate', { duration: formatDuration(estimatedTtl, $t) })}
        </div>
    {/if}

    {#if overLimit}
        <div class="notice warn" style="margin-bottom: 12px;">
            <strong>!</strong> {$t('create.too_large', { limit: formatBytes(serverConfig.max_paste_bytes) })}
        </div>
    {/if}
    {#if error}
        <div class="notice warn" style="margin-bottom: 12px;">
            <strong>!</strong> {$t(error)}
        </div>
    {/if}

    <div class="action-row">
        <button type="submit" disabled={submitting || overLimit || nothingToSend}>
            {#if !submitting}
                {$t('create.submit')}
            {:else if phase === 'captcha'}
                {$t('create.phase_captcha')}
            {:else if phase === 'pow'}
                {$t('create.phase_pow', { tries: Math.floor(powTries / 1000) + 'K' })}
            {:else if phase === 'encrypting'}
                {$t('create.phase_encrypting')}
            {:else}
                {$t('create.submitting')}
            {/if}
        </button>
    </div>
</form>
{:else}
<div class="card">
    <h2 class="card-title">{$t('result.title')}</h2>

    <div class="field">
        <div class="linkbox">
            <input type="text" readonly value={result.url} onclick={(e) => e.target.select()} />
            <button type="button" class="icon-btn lg"
                    class:ok={copied} class:error={copyError}
                    title={copyError ? $t('result.copy_failed') : copied ? $t('result.copied') : $t('result.copy')}
                    aria-label={$t('result.copy')}
                    onclick={copyLink}>
                {#if copyError}
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"
                         stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M4 4l8 8M12 4l-8 8" />
                    </svg>
                {:else if copied}
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"
                         stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M3 8.5l3 3 7-7" />
                    </svg>
                {:else}
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"
                         stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <rect x="5" y="5" width="8" height="9" rx="1.5" />
                        <path d="M3 11V3a1 1 0 0 1 1-1h7" />
                    </svg>
                {/if}
            </button>
            <button type="button" class="icon-btn lg"
                    title={$t('result.qr')} aria-label={$t('result.qr')}
                    onclick={() => showQr = true}>
                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.2"
                     aria-hidden="true">
                    <rect x="2" y="2" width="4" height="4" rx="0.5" />
                    <rect x="10" y="2" width="4" height="4" rx="0.5" />
                    <rect x="2" y="10" width="4" height="4" rx="0.5" />
                    <rect x="3.5" y="3.5" width="1" height="1" fill="currentColor" stroke="none" />
                    <rect x="11.5" y="3.5" width="1" height="1" fill="currentColor" stroke="none" />
                    <rect x="3.5" y="11.5" width="1" height="1" fill="currentColor" stroke="none" />
                    <path d="M8 2v3M8 8h3M11 11v3M14 8v3M8 14h3" stroke-linecap="round" />
                </svg>
            </button>
        </div>
    </div>

    {#if result.burn}
        <div class="notice warn">⚡ {$t('result.burn_warning')}</div>
    {/if}
    {#if result.hasPassword}
        <div class="notice" style="margin-top: 8px;">🔒 {$t('result.password_set')}</div>
    {/if}

    <dl class="meta-grid" style="margin-top: 14px;">
        <div><dt>{$t('view.meta_size')}</dt><dd>{formatBytes(result.size)}</dd></div>
        <div><dt>{$t('view.meta_expires')}</dt><dd>{formatDuration(result.ttl, $t)}</dd></div>
    </dl>

    <div class="action-row result-foot" style="margin-top: 16px;">
        <button class="ghost" onclick={reset}>{$t('result.new')}</button>
        <a class="delete-link" href={result.deleteUrl}>{$t('result.delete')}</a>
    </div>
</div>

{#if showQr}
    <QrModal url={result.url} onClose={() => showQr = false} />
{/if}
{/if}

<style>
    .dropzone.compact {
        padding: 14px 16px;
        text-align: left;
    }
    .dropzone.compact .file-info { margin-bottom: 4px; }
    .result-foot {
        justify-content: space-between;
    }
    .result-foot :global(button.ghost) {
        font-weight: 400;
    }
</style>
