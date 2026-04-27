// Render helpers for text / markdown / code views. All rendering happens
// after the ciphertext has been opened locally — the server never sees the
// rendered HTML.

import { marked } from 'marked';
import DOMPurify from 'dompurify';
import hljs from 'highlight.js/lib/common';

// A fixed shortlist surfaced in the language dropdown. highlight.js/common
// already bundles ~35 languages; we surface the most-used ones in a stable
// order. "auto" lets hljs guess.
export const LANGUAGES = [
    'auto', 'plaintext', 'bash', 'c', 'cpp', 'cmake', 'css', 'diff', 'dockerfile',
    'go', 'html', 'ini', 'java', 'javascript', 'json', 'kotlin', 'lua', 'makefile',
    'markdown', 'nginx', 'objectivec', 'perl', 'php', 'python', 'ruby', 'rust',
    'scss', 'shell', 'sql', 'swift', 'toml', 'typescript', 'xml', 'yaml'
];

export function renderMarkdown(src) {
    const html = marked.parse(src, { gfm: true });
    return DOMPurify.sanitize(html, { ADD_ATTR: ['target', 'rel'] });
}

export function renderCode(src, lang) {
    let html;
    try {
        if (!lang || lang === 'auto') {
            html = hljs.highlightAuto(src).value;
        } else if (hljs.getLanguage(lang)) {
            html = hljs.highlight(src, { language: lang, ignoreIllegals: true }).value;
        } else {
            html = escapeHtml(src);
        }
    } catch {
        html = escapeHtml(src);
    }
    return html;
}

function escapeHtml(s) {
    return s.replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}
