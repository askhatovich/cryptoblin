// Routing model. The path is always "/" — a non-existent SPA route never
// reaches the network; bookmark managers, browser-history sync, and stray
// reverse-proxy logs see only the bare "/" on initial load. Everything
// route-relevant lives in the URL fragment, which the browser does not
// transmit:
//
//   /                                    -> create page
//   /#<id>:<seed>                        -> view paste, no password prompt
//   /#<id>:<seed>:p                      -> view paste, prompt for password
//   /#del:<id>:<token>                   -> owner delete (creator-only link)

const FRAG_RE = /^([A-Za-z0-9]{8}):([A-Za-z0-9]{8})(?::(p))?$/;
const DEL_RE  = /^del:([A-Za-z0-9]{8}):([A-Za-z0-9+/=_-]+)$/;

export function parseLocation() {
    if (!location.hash || location.hash.length < 2) {
        return { route: 'create' };
    }
    const raw = decodeURIComponent(location.hash.slice(1));
    const md = DEL_RE.exec(raw);
    if (md) return { route: 'delete', id: md[1], token: md[2] };
    const m = FRAG_RE.exec(raw);
    if (!m) return { route: 'create' };
    return {
        route: 'view',
        id: m[1],
        seed: m[2],
        hasPassword: m[3] === 'p'
    };
}

export function buildPasteUrl(id, seed, hasPassword) {
    const tail = hasPassword ? `${id}:${seed}:p` : `${id}:${seed}`;
    return `${location.origin}/#${tail}`;
}

export function buildDeleteUrl(id, token) {
    return `${location.origin}/#del:${id}:${token}`;
}

export function navigateToPaste(id, seed, hasPassword) {
    const tail = hasPassword ? `${id}:${seed}:p` : `${id}:${seed}`;
    history.replaceState(null, '', '/');
    location.hash = tail;
}

export function navigateHome() {
    history.pushState(null, '', '/');
    window.dispatchEvent(new PopStateEvent('popstate'));
}
