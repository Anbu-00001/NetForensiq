import { createTheme } from '@mui/material/styles';
import * as t from './tokens';

/**
 * The visual identity.
 *
 * A white document, not a dark console. See tokens.js for why, and for the
 * measured contrast of every value used here.
 *
 * Deliberately NOT used: the State Emblem of India, the Ashoka Chakra as a
 * logo, or any Gujarat Police crest. The State Emblem of India (Prohibition of
 * Improper Use) Act 2005 restricts the emblem to the authorities it names, and
 * a hackathon entry is not one of them.
 */

const theme = createTheme({
  palette: {
    mode: 'light',
    background: { default: t.PAPER, paper: t.PAPER },
    primary: { main: t.INK, contrastText: t.PAPER },
    secondary: { main: t.CYAN, contrastText: t.PAPER },
    error: { main: t.CRITICAL },
    warning: { main: t.MEDIUM },
    success: { main: t.INTACT },
    info: { main: t.CYAN },
    text: { primary: t.INK, secondary: t.GREY },
    divider: t.RULE,

    /**
     * Named for what they mean here, not for what colour they are, so a
     * component asks for `forensic.intact` rather than "the green one" and the
     * meaning survives a change of palette.
     */
    forensic: {
      critical: t.CRITICAL,
      high: t.HIGH,
      medium: t.MEDIUM,
      low: t.LOW,
      info: t.INFO,

      intact: t.INTACT,
      broken: t.BROKEN,
      unattested: t.UNATTESTED,

      internal: t.INTERNAL,
      external: t.EXTERNAL,
      hostile: t.HOSTILE,

      paper: t.PAPER,
      panel: t.PANEL,
      panelAlt: t.PANEL_ALT,
      rule: t.RULE,
      ruleStrong: t.RULE_STRONG,
      ink: t.INK,
      inkSoft: t.INK_SOFT,
      grey: t.GREY,
      greyMuted: t.GREY_MUTED,

      cyan: t.CYAN,
      cyanFill: t.CYAN_FILL,
      cyanBright: t.CYAN_BRIGHT,
      cyanWash: t.CYAN_WASH,

      series: t.SERIES,
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
    mono: t.MONO,
  },
  shape: {
    // Government forms and registers are rectangular. Heavy rounding reads as
    // consumer software.
    borderRadius: 3,
  },
  components: {
    // Separation comes from a rule, never from a shadow. A drop shadow on a
    // white ground is the thing that makes an interface look like a mockup.
    MuiPaper: {
      styleOverrides: {
        root: { backgroundImage: 'none', boxShadow: 'none' },
        outlined: { borderColor: t.RULE },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: { boxShadow: 'none', '&:hover': { boxShadow: 'none' } },
      },
    },
  },
});

export default theme;
