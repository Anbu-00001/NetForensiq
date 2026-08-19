import { useEffect, useRef } from 'react';
import { Box } from '@mui/material';

/**
 * A pane of glass, with depth that responds to where the reader is looking.
 *
 * Why depth here and nowhere else
 * -------------------------------
 * The rest of this product is deliberately flat: a case file, a register, a
 * certificate. Depth on a data table is noise. The landing page has a
 * different job — it is the ten seconds before anyone believes the tool is
 * serious — and a surface that behaves like a real material is the cheapest
 * honest signal that something was built rather than assembled.
 *
 * So the effect is spent in one place, on the panel that explains what the
 * product does, and it is built from the three things that actually make a
 * surface read as glass:
 *
 *   1. **Refraction.** The panel is translucent and blurs what is behind it,
 *      so the ruled ground of the hero shows through, softened. A panel with
 *      nothing behind it cannot look like glass no matter how it is shaded —
 *      which is why the hero has a grid at all.
 *   2. **Parallax.** Tilting on pointer position, with the contents sitting on
 *      a raised plane inside the same 3D context. The lift between the surface
 *      and its contents is what the eye reads as thickness; a flat card that
 *      merely rotates reads as a sheet of paper.
 *   3. **Specular.** A soft highlight tracking the pointer. It is *white*, not
 *      a colour — on a translucent panel a white sheen locally raises the
 *      opacity and hides the grid behind it, which is exactly what light does
 *      on real glass. It also means the effect introduces no new hue, so the
 *      palette rule holds: every coloured pixel in this product still means
 *      something.
 *
 * What it deliberately is not
 * ---------------------------
 * No WebGL, no shader, no particle field. This runs on a police workstation
 * with integrated graphics, offline, and may be projected. Everything here is
 * compositor work the browser was going to do anyway — two transforms and a
 * gradient — so it costs no frame budget and degrades to a plain frosted card
 * if any of it is unsupported.
 *
 * Tilt is off for a coarse pointer (there is no hover on a touchscreen, so it
 * would only ever fire mid-tap) and off entirely under
 * `prefers-reduced-motion`, which is an accessibility setting and not a
 * preference to override.
 */

const TILT_SETTLE = 'transform 0.45s cubic-bezier(0.22,1,0.36,1)';

function GlassPanel({
  children,
  maxTilt = 5,
  sheen = 260,
  sx = {},
  ...rest
}) {
  const ref = useRef(null);
  const frame = useRef(0);

  useEffect(() => {
    const el = ref.current;
    if (!el) return undefined;

    const fine = window.matchMedia?.('(hover: hover) and (pointer: fine)');
    const still = window.matchMedia?.('(prefers-reduced-motion: reduce)');
    if (still?.matches || !fine?.matches) return undefined;

    const move = (event) => {
      const rect = el.getBoundingClientRect();
      const px = (event.clientX - rect.left) / rect.width;
      const py = (event.clientY - rect.top) / rect.height;
      cancelAnimationFrame(frame.current);
      // Coalesced into one frame: pointermove fires far faster than the
      // compositor can use, and writing a style per event is how a hover
      // effect turns into jank on the machine it will actually be shown on.
      frame.current = requestAnimationFrame(() => {
        el.style.setProperty('--mx', `${px * 100}%`);
        el.style.setProperty('--my', `${py * 100}%`);
        el.style.setProperty('--rx', `${(0.5 - py) * 2 * maxTilt}deg`);
        el.style.setProperty('--ry', `${(px - 0.5) * 2 * maxTilt}deg`);
        el.style.setProperty('--lit', '1');
      });
    };

    const leave = () => {
      cancelAnimationFrame(frame.current);
      el.style.setProperty('--rx', '0deg');
      el.style.setProperty('--ry', '0deg');
      el.style.setProperty('--lit', '0');
    };

    el.addEventListener('pointermove', move);
    el.addEventListener('pointerleave', leave);
    return () => {
      cancelAnimationFrame(frame.current);
      el.removeEventListener('pointermove', move);
      el.removeEventListener('pointerleave', leave);
    };
  }, [maxTilt]);

  return (
    <Box
      ref={ref}
      {...rest}
      sx={{
        position: 'relative',
        // Custom properties declared here so the panel has a defined resting
        // state before any pointer has touched it — and so it still looks
        // right if the effect never attaches.
        '--rx': '0deg',
        '--ry': '0deg',
        '--mx': '50%',
        '--my': '0%',
        '--lit': 0,

        transformStyle: 'preserve-3d',
        transform:
          'perspective(1000px) rotateX(var(--rx)) rotateY(var(--ry))',
        transition: TILT_SETTLE,
        willChange: 'transform',

        backgroundColor: 'rgba(255,255,255,0.58)',
        backdropFilter: 'blur(20px) saturate(1.25)',
        WebkitBackdropFilter: 'blur(20px) saturate(1.25)',
        border: '1px solid rgba(255,255,255,0.92)',
        borderRadius: 2,
        // The dark hairline is what keeps a white panel on a white page from
        // dissolving into it. Inset, so it reads as the edge of the glass
        // rather than as a drawn border.
        outline: '1px solid rgba(17,19,21,0.07)',
        outlineOffset: '-1px',

        // Three shadows doing three separate jobs: a lit top edge inside the
        // glass, a long soft cast for elevation, and a short tight one for
        // contact with the page. A single shadow reads as a sticker.
        boxShadow: `
          0 1px 0 rgba(255,255,255,0.95) inset,
          0 26px 54px -30px rgba(17,19,21,0.34),
          0 3px 9px -5px rgba(17,19,21,0.11)
        `,

        // The specular highlight.
        '&::before': {
          content: '""',
          position: 'absolute',
          inset: 0,
          borderRadius: 'inherit',
          pointerEvents: 'none',
          background: `radial-gradient(${sheen}px circle at var(--mx) var(--my), rgba(255,255,255,0.85), rgba(255,255,255,0) 70%)`,
          opacity: 'var(--lit)',
          transition: 'opacity 0.35s ease',
          mixBlendMode: 'screen',
        },

        // The lit top edge, brightening as the panel tips towards the light.
        '&::after': {
          content: '""',
          position: 'absolute',
          left: 12,
          right: 12,
          top: 0,
          height: '1px',
          pointerEvents: 'none',
          background:
            'linear-gradient(90deg, transparent, rgba(255,255,255,0.98), transparent)',
          opacity: 'calc(0.45 + var(--lit) * 0.55)',
          transition: 'opacity 0.35s ease',
        },

        ...sx,
      }}
    >
      {children}
    </Box>
  );
}

/**
 * Contents raised off the surface of the glass.
 *
 * This is the part that makes the panel read as a solid object rather than a
 * rotating rectangle: at the tilt angles used here, a 20px lift moves the
 * contents a couple of pixels against the surface, which is the same cue the
 * eye uses to judge thickness through a shop window.
 */
export function Lift({ z = 18, children, sx = {}, ...rest }) {
  return (
    <Box
      {...rest}
      sx={{
        transform: `translateZ(${z}px)`,
        transformStyle: 'preserve-3d',
        ...sx,
      }}
    >
      {children}
    </Box>
  );
}

export default GlassPanel;
