<script>
    import { onMount } from 'svelte';
    import QRCode from 'qrcode';
    import { t } from '../lib/i18n.js';

    let { url, onClose } = $props();
    let canvasEl;

    onMount(() => {
        QRCode.toCanvas(canvasEl, url, {
            errorCorrectionLevel: 'M',
            margin: 2,
            width: 280,
            color: { dark: '#0a0e22', light: '#ffffff' }
        });
    });
</script>

<svelte:window onkeydown={(e) => { if (e.key === 'Escape') onClose && onClose(); }} />

<div class="backdrop" role="presentation" onclick={onClose}>
    <div
        class="modal"
        role="dialog"
        aria-modal="true"
        tabindex="-1"
        onclick={(e) => e.stopPropagation()}
        onkeydown={(e) => e.stopPropagation()}
    >
        <h2>{$t('result.qr_title')}</h2>
        <canvas bind:this={canvasEl}></canvas>
        <div class="link mono dim">{url}</div>
        <button class="ghost" onclick={onClose}>{$t('result.qr_close')}</button>
    </div>
</div>

<style>
    .backdrop {
        position: fixed; inset: 0;
        background: rgba(0, 0, 0, 0.55);
        display: flex; align-items: center; justify-content: center;
        z-index: 1000;
        animation: fade-in 0.16s ease-out;
        padding: 16px;
    }
    .modal {
        background: var(--bg-elev);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        box-shadow: var(--shadow);
        padding: 22px;
        max-width: 360px;
        width: 100%;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 14px;
    }
    h2 { margin: 0; font-size: 18px; }
    canvas { max-width: 100%; height: auto; border-radius: 6px; }
    .link {
        font-size: 11px;
        word-break: break-all;
        text-align: center;
    }
    button { width: 100%; }
</style>
