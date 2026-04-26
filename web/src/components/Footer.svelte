<script>
    import { t } from '../lib/i18n.js';
    import { VERSION } from '../version.js';
</script>

<footer class="footer">
    <p class="blurb dim">{$t('app.privacy_blurb')}</p>
    <p class="copyright">
        <a class="brand" href="https://github.com/askhatovich/cryptoblin"
           target="_blank" rel="noopener noreferrer">CryptoBlin</a>
        <span class="dot">·</span>
        <span class="version mono">v{VERSION}</span>
    </p>
</footer>

<style>
    .footer {
        margin-top: auto;
        padding-top: 22px;
        font-size: 12px;
        color: var(--text-dim);
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 18px;
        flex-wrap: wrap;
    }
    .blurb {
        margin: 0;
        flex: 1 1 60ch;
        max-width: 60ch;
        font-size: 11.5px;
        line-height: 1.55;
        opacity: 0.85;
        text-align: left;
    }
    .copyright {
        margin: 0;
        flex: 0 0 auto;
        text-align: right;
        white-space: nowrap;
    }
    .copyright .brand   { color: var(--accent); font-weight: 600; text-decoration: none; }
    .copyright .brand:hover { text-decoration: underline; }
    .copyright .dot     { opacity: 0.4; margin: 0 6px; }
    .copyright .version { font-size: 11px; }
</style>
