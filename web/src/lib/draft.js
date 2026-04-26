// Hand-off between View ("Create copy") and Create. Module-level store kept
// in memory only — never persisted. View sets it just before navigating
// home; Create reads and clears it on mount, so a refresh of the empty
// home page does not bring the prior content back.

let pending = null;

export function setDraft(d) { pending = d; }
export function popDraft() {
    const d = pending;
    pending = null;
    return d;
}
