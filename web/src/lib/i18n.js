import { writable, derived } from 'svelte/store';
import { storage } from './storage.js';
import { en } from '../locales/en.js';
import { ru } from '../locales/ru.js';
import { de } from '../locales/de.js';
import { es } from '../locales/es.js';

const DICT = { en, ru, de, es };

function detect() {
    const saved = storage.getLang();
    if (saved && DICT[saved]) return saved;
    const browser = (navigator.language || 'en').slice(0, 2).toLowerCase();
    return DICT[browser] ? browser : 'en';
}

export const lang = writable(detect());
lang.subscribe(v => storage.setLang(v));

export const t = derived(lang, $lang => {
    return (key, vars) => {
        const parts = key.split('.');
        let node = DICT[$lang] || DICT.en;
        for (const p of parts) {
            if (node && typeof node === 'object' && p in node) node = node[p];
            else return key;
        }
        let s = typeof node === 'string' ? node : key;
        if (vars) {
            for (const k of Object.keys(vars)) {
                s = s.replace(new RegExp(`\\{${k}\\}`, 'g'), String(vars[k]));
            }
        }
        return s;
    };
});
