// localStorage wrapper. Only stores user preferences — never paste content,
// never keys, never passwords.

const NS = 'cryptoblin.';

export const storage = {
    getLang() { return localStorage.getItem(NS + 'lang') || ''; },
    setLang(l) { localStorage.setItem(NS + 'lang', l); },
    getTheme() { return localStorage.getItem(NS + 'theme') || 'dark'; },
    setTheme(t) { localStorage.setItem(NS + 'theme', t); }
};
