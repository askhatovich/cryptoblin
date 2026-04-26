<script>
    import { onMount, onDestroy } from 'svelte';
    import { t } from '../lib/i18n.js';
    import { api } from '../lib/api.js';
    import {
        deriveKey, solveChallenge, openEnvelope, toB64, fromB64,
        CHALLENGE_BURN_OFFSET
    } from '../lib/crypto.js';
    import {
        unpackPayload, FORMAT, FORMAT_NAME, suggestedTextFilename
    } from '../lib/payload.js';
    import { renderMarkdown, renderCode } from '../lib/format.js';
    import { formatBytes, formatDuration, downloadBytes, copyText } from '../lib/util.js';
    import { navigateHome } from '../lib/urlfrag.js';
    import { setDraft } from '../lib/draft.js';

    let { id, seed, hasPassword } = $props();

    let phase = $state('loading');
    let openResp = $state(null);
    let key = $state(null);
    let password = $state('');
    let passwordError = $state(false);
    let error = $state(null);
    let payload = $state(null);
    let copied = $state(false);
    let copyError = $state(false);
    let burnFlag = $state(false);
    let meta = $state(null);

    let progress = $state(0);
    let downloaded = $state(0);
    let totalSize = $state(0);

    let now = $state(Math.floor(Date.now() / 1000));
    let secondsLeft = $derived(Math.max(0, (meta?.expiresAt || 0) - now));
    let timer;
    onMount(() => { timer = setInterval(() => { now = Math.floor(Date.now() / 1000); }, 1000); });
    onDestroy(() => { if (timer) clearInterval(timer); });

    let passwordInput = $state(null);
    $effect(() => {
        if (phase === 'need_password' && passwordInput) passwordInput.focus();
    });

    onMount(async () => {
        if (!seed) { phase = 'error'; error = 'errors.bad_envelope'; return; }
        try {
            openResp = await api.openPaste(id);
        } catch (e) {
            phase = 'error';
            error = 'errors.' + (e.code === 'http_404' ? 'not_found' : (e.code || 'network'));
            return;
        }
        if (hasPassword) { phase = 'need_password'; return; }
        await deriveAndSolve('');
    });

    let challengePlaintext = $state(null);
    async function deriveAndSolve(pwd) {
        phase = 'need_solve';
        try {
            key = await deriveKey(seed, pwd || '');
            const nonce      = await fromB64(openResp.challenge.nonce);
            const ciphertext = await fromB64(openResp.challenge.ciphertext);
            challengePlaintext = await solveChallenge(nonce, ciphertext, key);
            burnFlag = challengePlaintext[CHALLENGE_BURN_OFFSET] === 1;
            phase = 'ready_to_open';
            if (!burnFlag) await downloadAndDecrypt();
        } catch {
            if (hasPassword) { phase = 'need_password'; passwordError = true; }
            else             { phase = 'error'; error = 'errors.bad_key'; }
        }
    }

    function submitPassword(e) {
        e?.preventDefault?.();
        passwordError = false;
        deriveAndSolve(password);
    }

    async function downloadAndDecrypt() {
        phase = 'downloading';
        progress = 0; downloaded = 0; totalSize = 0;
        try {
            const ptB64 = await toB64(challengePlaintext);
            const got = await api.fetchBlob(id, openResp.token, ptB64, (recv, total) => {
                downloaded = recv;
                totalSize  = total || recv;
                progress   = totalSize ? recv / totalSize : 0;
            });
            const plaintext = await openEnvelope(got.bytes, key);
            payload = unpackPayload(plaintext);
            meta = {
                size:      got.size,
                createdAt: got.createdAt,
                expiresAt: got.expiresAt,
                viewCount: got.views,
                burn:      got.burned
            };
            phase = 'ready';
        } catch (e) {
            phase = 'error';
            const c = e?.code;
            if (c === 'bad_key' || c === 'http_403') error = 'errors.bad_key';
            else if (c === 'http_404' || c === 'not_found') error = 'errors.not_found';
            else error = 'errors.' + (c || 'network');
        }
    }

    async function copyTextBody() {
        if (!payload?.text) return;
        copyError = false;
        try {
            await copyText(payload.text);
            copied = true;
            setTimeout(() => { copied = false; }, 1400);
        } catch {
            copyError = true;
            setTimeout(() => { copyError = false; }, 1800);
        }
    }

    // Save the rendered/source text as a file with an extension picked from
    // the format + language. Always saves the SOURCE text — so a markdown
    // note saves as .md (not the rendered HTML).
    function saveTextAsFile() {
        if (!payload?.text) return;
        const fname = suggestedTextFilename(payload.format, payload.lang);
        const bytes = new TextEncoder().encode(payload.text);
        downloadBytes(bytes, fname, 'text/plain;charset=utf-8');
    }

    function downloadFile() {
        if (!payload?.file) return;
        downloadBytes(payload.file.body, payload.file.name || 'file', payload.file.mime);
    }

    // Open the source text in a new tab as text/plain so the user can
    // copy it without formatting (the original markdown / code source).
    let rawTabUrl = $state(null);
    function showRaw() {
        if (!payload?.text) return;
        const blob = new Blob([payload.text], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        if (rawTabUrl) URL.revokeObjectURL(rawTabUrl);
        rawTabUrl = url;
        window.open(url, '_blank', 'noopener,noreferrer');
    }
    onDestroy(() => { if (rawTabUrl) URL.revokeObjectURL(rawTabUrl); });

    // "Create copy" — hand the decrypted content to the create page via an
    // in-memory store and navigate home. The content is never persisted.
    function createCopy() {
        if (!payload) return;
        setDraft({
            format: payload.format,
            lang:   payload.lang,
            text:   payload.text,
            file:   payload.file
                ? { name: payload.file.name, mime: payload.file.mime, body: payload.file.body }
                : null
        });
        navigateHome();
    }

    let renderedHtml = $derived.by(() => {
        if (!payload?.text) return '';
        if (payload.format === FORMAT.MARKDOWN) return renderMarkdown(payload.text);
        if (payload.format === FORMAT.CODE)     return renderCode(payload.text, payload.lang || 'auto');
        return '';
    });

    function isImage(m) { return typeof m === 'string' && m.startsWith('image/'); }
    function isPdf(m)   { return m === 'application/pdf'; }
    let objectUrl = $state(null);
    $effect(() => {
        if (payload?.file && (isImage(payload.file.mime) || isPdf(payload.file.mime))) {
            const blob = new Blob([payload.file.body], { type: payload.file.mime });
            objectUrl = URL.createObjectURL(blob);
            return () => { URL.revokeObjectURL(objectUrl); objectUrl = null; };
        }
    });
</script>

<div class="card">
    {#if phase === 'loading'}
        <div class="dim">{$t('view.loading_meta')}</div>
    {:else if phase === 'need_password'}
        <form onsubmit={submitPassword}>
            <h2 class="card-title">🔒 {$t('view.password_required')}</h2>
            <div class="field">
                <label for="pwd">{$t('view.password_input')}</label>
                <input id="pwd" type="password" bind:value={password} bind:this={passwordInput} />
                {#if passwordError}
                    <div class="hint" style="color: var(--danger);">{$t('view.password_wrong')}</div>
                {/if}
            </div>
            <button type="submit">{$t('view.password_submit')}</button>
        </form>
    {:else if phase === 'need_solve'}
        <div class="dim">{$t('view.loading')}</div>
    {:else if phase === 'ready_to_open'}
        {#if burnFlag}
            <h2 class="card-title">⚡ {$t('view.burn_warning_title')}</h2>
            <div class="notice warn">{$t('view.burn_warning_body')}</div>
            <div class="action-row" style="margin-top: 14px;">
                <button class="danger" onclick={downloadAndDecrypt}>{$t('view.burn_continue')}</button>
                <button class="ghost" onclick={() => navigateHome()}>{$t('view.burn_cancel')}</button>
            </div>
        {:else}
            <div class="dim">{$t('view.loading')}</div>
        {/if}
    {:else if phase === 'downloading'}
        <div style="margin-bottom: 8px;">{$t('view.loading')}</div>
        <div class="progress"><div class="bar" style="width: {(progress * 100).toFixed(1)}%"></div></div>
        <div class="dim" style="margin-top: 6px; font-size: 12px;">
            {formatBytes(downloaded)} / {formatBytes(totalSize || openResp.meta.size)}
        </div>
    {:else if phase === 'error'}
        <div class="notice warn"><strong>!</strong> {$t(error || 'errors.internal')}</div>
    {:else if phase === 'ready' && payload}
        {#if payload.text}
            <div class="subtle-actions">
                <button type="button" class="link-btn" onclick={showRaw}>{$t('view.show_raw')}</button>
                {#if !payload.file}
                    <button type="button" class="link-btn" onclick={createCopy}>{$t('view.create_copy')}</button>
                {/if}
            </div>
        {/if}
        <!-- Text part. -->
        {#if payload.text}
            {#snippet textActions()}
                <div class="viewer-actions">
                    <button type="button" class="icon-btn"
                            class:ok={copied} class:error={copyError}
                            title={copyError ? $t('view.copy_failed') : copied ? $t('view.copied') : $t('view.copy_text')}
                            aria-label={$t('view.copy_text')}
                            onclick={copyTextBody}>
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
                    <button type="button" class="icon-btn"
                            title={$t('view.save_text_as_file')}
                            aria-label={$t('view.save_text_as_file')}
                            onclick={saveTextAsFile}>
                        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"
                             stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                            <path d="M8 2v8" />
                            <path d="M4.5 7.5L8 11l3.5-3.5" />
                            <path d="M3 13h10" />
                        </svg>
                    </button>
                </div>
            {/snippet}
            {#if payload.format === FORMAT.MARKDOWN}
                <div class="viewer markdown with-actions">
                    {@render textActions()}
                    {@html renderedHtml}
                </div>
            {:else if payload.format === FORMAT.CODE}
                <div class="viewer with-actions">
                    {@render textActions()}
                    <div class="code-meta dim">
                        {payload.lang || 'auto'}
                    </div>
                    <pre class="code hljs">{@html renderedHtml}</pre>
                </div>
            {:else}
                <div class="viewer with-actions">
                    {@render textActions()}
                    <pre>{payload.text}</pre>
                </div>
            {/if}
        {/if}

        <!-- File part. -->
        {#if payload.file}
            <div class="file-block" class:after-text={!!payload.text}>
                <div class="file-head">
                    <span class="mono">📎 {payload.file.name || 'file'}</span>
                    <span class="dim"> · {formatBytes(payload.file.body.length)}{payload.file.mime ? ' · ' + payload.file.mime : ''}</span>
                </div>
                {#if objectUrl && isImage(payload.file.mime)}
                    <div class="viewer"><img src={objectUrl} alt={payload.file.name} style="max-width:100%;" /></div>
                {:else if objectUrl && isPdf(payload.file.mime)}
                    <div class="viewer" style="padding: 0;">
                        <iframe src={objectUrl} title={payload.file.name} style="width:100%; height:70vh; border:0;"></iframe>
                    </div>
                {/if}
                <div class="action-row" style="margin-top: 8px;">
                    <button onclick={downloadFile}>{$t('view.download_file')}</button>
                </div>
            </div>
        {/if}

    {/if}
</div>

{#if meta}
<div class="card meta-card">
    <dl class="meta-grid">
        <div><dt>{$t('view.meta_size')}</dt><dd>{formatBytes(meta.size)}</dd></div>
        <div><dt>{$t('view.meta_created')}</dt><dd>{new Date(meta.createdAt * 1000).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })}</dd></div>
        <div><dt>{$t('view.meta_expires')}</dt><dd>{secondsLeft > 0 ? formatDuration(secondsLeft, $t) : '—'}</dd></div>
        <div><dt>{$t('view.meta_views')}</dt><dd>{meta.viewCount}</dd></div>
    </dl>
</div>
{/if}

<style>
    .progress {
        width: 100%;
        height: 6px;
        background: var(--bg-elev-2);
        border-radius: 999px;
        overflow: hidden;
    }
    .bar {
        height: 100%;
        background: var(--accent);
        transition: width 0.2s ease;
    }
    .file-block.after-text {
        margin-top: 14px;
        padding-top: 14px;
        border-top: 1px solid var(--border);
    }
    .file-head {
        font-size: 13px;
        margin-bottom: 8px;
    }
    .code-meta {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 6px;
    }
</style>
