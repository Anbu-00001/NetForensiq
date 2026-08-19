/**
 * The palette, as measured values rather than remembered ones.
 *
 * Why the interface is white
 * -------------------------
 * The earlier build was a dark console with a neon cyan accent. That is the
 * default look of every generated dashboard on the internet, and it is also
 * the wrong metaphor: this tool's output is a document that a magistrate
 * reads. Paper-white with black text and hairline rules is what a register,
 * a form and a forensic report actually look like, and it is what survives
 * being printed, projected in a lit room, or photographed off a screen.
 *
 * Where the colour went
 * ---------------------
 * Colour is reserved for things that carry a forensic or legal meaning —
 * severity, seal state, which side of the monitored network a host sits on.
 * Nothing is coloured for decoration. That is the rule that keeps a serious
 * instrument from looking like a marketing page, and it means every coloured
 * pixel on screen is answerable: an officer can ask "why is that red" and
 * there is always an answer.
 *
 * The cyan
 * --------
 * One accent, two values, because a single hex cannot serve both grounds.
 * CYAN measures 5.95:1 on paper; CYAN_BRIGHT measures 1.77:1 there — unusable
 * — but 10.52:1 on ink, so it is kept for the dark strips only. Reaching for
 * the bright one on a white surface is the single easiest way to break this
 * palette, which is why they are named for where they go, not for how they
 * look.
 *
 * Every value below is checked on every build by scripts/check_palette.py,
 * which recomputes WCAG 2.1 relative luminance from these exact constants and
 * fails if any text token drops under 4.5:1 against either ground.
 */

// ── grounds ────────────────────────────────────────────────────────────────
export const PAPER = '#FFFFFF';      // the page
export const PANEL = '#F4F5F7';      // a raised surface
export const PANEL_ALT = '#ECEEF1';  // table stripe, row hover
export const RULE = '#E2E5E9';       // hairline border — the separator of choice
export const RULE_STRONG = '#C7CCD2';

// ── ink ────────────────────────────────────────────────────────────────────
export const INK = '#111315';        // 18.62:1 on paper
export const INK_SOFT = '#2B3138';   // 13.13:1 — secondary headings
export const GREY = '#5A6068';       //  6.35:1 — secondary text
export const GREY_MUTED = '#6B7178'; //  4.93:1 — the floor; nothing dimmer exists

// ── the accent ─────────────────────────────────────────────────────────────
export const CYAN = '#076E7C';        // 5.95:1 on paper — links, focus, active nav
export const CYAN_FILL = '#0891A8';   // 3.73:1 — graphics only, never text
export const CYAN_BRIGHT = '#00D4FF'; // 10.52:1 on INK — dark strips only
export const CYAN_WASH = '#E6F4F7';   // selected row, chip ground

// The other on-ink value: the handling marking when it rises above
// unclassified. 11.10:1 on INK, 1.68:1 on paper — dark strips only, same rule.
export const AMBER_BRIGHT = '#F0C24A';

// ── meaning ────────────────────────────────────────────────────────────────
export const CRITICAL = '#B3261E';
export const HIGH = '#B45309';
export const MEDIUM = '#8A6100';
export const LOW = '#1F3A5F';
export const INFO = GREY;

export const INTACT = '#1B6E3C';      // seal verified
export const BROKEN = CRITICAL;       // seal fails to verify
export const UNATTESTED = MEDIUM;     // provenance not established

export const INTERNAL = LOW;          // a host inside the monitored network
export const EXTERNAL = HIGH;         // anything outside it
export const HOSTILE = CRITICAL;      // an endpoint a rule has implicated

// A sixth hue for charts that need one. It means nothing on its own — it is
// there so two adjacent series are distinguishable, not to signal anything.
export const VIOLET = '#6B4FA8';

// Pressed and hover states. Each is its own colour darkened, never a shadow
// or a lift, so a button under the cursor still looks like the same button.
export const CRITICAL_DEEP = '#8F1E17';
export const HIGH_DEEP = '#8F4207';
export const MEDIUM_DEEP = '#6F4E00';
export const INTACT_DEEP = '#155B31';
export const LOW_DEEP = '#16406B';
export const VIOLET_DEEP = '#5A3F93';

export const SERIES = [LOW, CYAN, HIGH, INTACT, VIOLET, CRITICAL];

export const MONO = "'JetBrains Mono', ui-monospace, monospace";
