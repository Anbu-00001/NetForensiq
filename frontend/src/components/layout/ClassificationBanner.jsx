import { Box, Typography } from '@mui/material';
import { INK, CYAN_BRIGHT, AMBER_BRIGHT, PAPER, MONO } from '../../theme/tokens';

/**
 * The handling marking for whatever is currently on screen.
 *
 * Why a whole bar for one line of text
 * ------------------------------------
 * Every high-assurance system this tool would sit beside carries one, for a
 * practical reason: a person walking past a monitor, or a photograph of that
 * monitor, must show what may be done with what is displayed. The reference
 * pattern repeats it at the top and bottom of the page; here it is sticky
 * instead, which achieves the same thing — it cannot be scrolled off — with
 * one element rather than two.
 *
 * Why the level changes
 * ---------------------
 * A banner that always says the same thing stops being read within a day. On
 * the sign-in and public pages there genuinely is no case material on screen,
 * and saying otherwise would be theatre — so those pages are marked
 * UNCLASSIFIED and say why. The marking only rises once evidence is on the
 * page, which is the point at which the operator needs to see it.
 *
 * NOT a security control. It is a label, and the API enforces the actual
 * permissions. Anything that reads this as protection has misread it.
 */

const LEVELS = {
  unclassified: {
    text: 'UNCLASSIFIED',
    accent: CYAN_BRIGHT,
    detail: 'NO CASE MATERIAL ON THIS SCREEN',
  },
  restricted: {
    text: 'RESTRICTED',
    accent: AMBER_BRIGHT,
    detail: 'EVIDENTIARY MATERIAL · AUTHORISED PERSONNEL ONLY',
  },
};

export const BANNER_HEIGHT = 26;

function ClassificationBanner({ level = 'unclassified', detail, position = 'top', fixed = false }) {
  const spec = LEVELS[level] ?? LEVELS.unclassified;

  return (
    <Box
      component="aside"
      aria-label={`Handling marking: ${spec.text}`}
      sx={{
        height: BANNER_HEIGHT,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 1.5,
        px: 2,
        backgroundColor: INK,
        // A hairline in the level's own colour, on the edge that faces the
        // page, so the bar reads as an edge of the document rather than a
        // floating element.
        [position === 'top' ? 'borderBottom' : 'borderTop']: `2px solid ${spec.accent}`,
        overflow: 'hidden',
        whiteSpace: 'nowrap',
        // Inside the application the marking covers the navigation as well as
        // the content, because it describes the screen, not one column of it.
        ...(fixed && { position: 'fixed', top: 0, left: 0, right: 0, zIndex: 1400 }),
      }}
    >
      <Typography
        component="span"
        sx={{
          fontFamily: MONO, fontSize: 10.5, fontWeight: 700,
          letterSpacing: 2, color: spec.accent,
        }}
      >
        {spec.text}
      </Typography>
      <Typography
        component="span"
        sx={{
          fontFamily: MONO, fontSize: 10, letterSpacing: 1.1, color: PAPER,
          opacity: 0.72, display: { xs: 'none', sm: 'block' },
        }}
      >
        {detail ?? spec.detail}
      </Typography>
    </Box>
  );
}

export default ClassificationBanner;
