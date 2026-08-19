import { createTheme } from '@mui/material/styles';

/**
 * The visual identity.
 *
 * This replaces a generic dark-cyan admin palette that could have belonged to
 * any SaaS dashboard. What is on screen is meant to read, immediately, as an
 * Indian government forensic instrument: the ground is the deep navy of
 * government print, the action colour is saffron, intact evidence is the green
 * of the flag, and the brass tone is the one an officer sees on their own
 * uniform every day.
 *
 * Deliberately NOT used: the State Emblem of India, the Ashoka Chakra as a
 * logo, or any Gujarat Police crest. The State Emblem of India (Prohibition of
 * Improper Use) Act 2005 restricts the emblem's use to the authorities it
 * names, and a hackathon entry is not one of them. Evoking the palette is
 * legitimate; wearing the insignia is not.
 *
 * Every value below was measured against the two background tones before being
 * committed: all pass WCAG 2.1 AA for normal text (4.5:1), which the browser
 * suite re-checks on every build. The lowest is 5.24:1.
 */

// The two grounds. Everything else is measured against these.
const INK = '#0B1020';      // page — deep government navy, near-black
const SLATE = '#141B2E';    // raised surfaces

const theme = createTheme({
  palette: {
    mode: 'dark',
    background: {
      default: INK,
      paper: SLATE,
    },
    primary: {
      // Saffron. The action colour, and the one an Indian reader reads as
      // "attend to this" without being told.
      main: '#FF9933',
      contrastText: INK,
    },
    secondary: {
      // Chakra blue, for supporting and navigational emphasis.
      main: '#5B8DEF',
      contrastText: '#FFFFFF',
    },
    error: { main: '#FF6B6B' },
    warning: { main: '#E8C24A' },
    success: { main: '#3FD873' },
    text: {
      primary: '#E8ECF4',
      secondary: '#A7B0C4',
    },
    divider: 'rgba(167,176,196,0.16)',

    /**
     * Named for what they mean here, not for what colour they are, so a
     * component asks for `verdict.confirmed` rather than "the green one" and
     * the meaning survives a change of palette.
     */
    forensic: {
      // Severity, in the order a court would rank it.
      critical: '#FF6B6B',
      high: '#FF9933',
      medium: '#E8C24A',
      low: '#5B8DEF',
      info: '#A7B0C4',

      // Evidentiary state.
      intact: '#3FD873',
      broken: '#FF6B6B',
      unattested: '#E8C24A',

      // Identity of the two sides of a conversation, used consistently by the
      // map, the timeline and the flow tables so the same machine is the same
      // colour wherever it appears.
      internal: '#5B8DEF',   // a host inside the monitored network
      external: '#FF9933',   // anything outside it
      hostile: '#FF6B6B',    // an endpoint a rule has implicated

      brass: '#E8C24A',      // the police accent
      ink: INK,
      slate: SLATE,
    },
  },
  typography: {
    // Inter for prose; JetBrains Mono wherever a value must be compared
    // character by character — a hash, an IP, an exhibit number. Both are
    // bundled locally, so they render on an air-gapped machine.
    fontFamily: "'Inter', 'Noto Sans Gujarati', sans-serif",
    h1: { fontWeight: 700, letterSpacing: '-0.02em' },
    h2: { fontWeight: 700, letterSpacing: '-0.02em' },
    h3: { fontWeight: 700, letterSpacing: '-0.01em' },
    h4: { fontWeight: 700 },
    h5: { fontWeight: 600 },
    h6: { fontWeight: 600 },
    button: { fontWeight: 600, textTransform: 'none', letterSpacing: '0.01em' },
    // For anything an officer might read aloud in court.
    mono: "'JetBrains Mono', ui-monospace, monospace",
  },
  shape: {
    // Squarer than the previous 6px. Government forms and registers are
    // rectangular; heavy rounding reads as consumer software.
    borderRadius: 4,
  },
});

export default theme;
