import { useMemo } from 'react';

/**
 * The ground the hero's glass refracts.
 *
 * The problem
 * -----------
 * A frosted panel on a white page is just a white rectangle. Glass is only
 * legible when there is something behind it being bent — the blur has to have
 * an argument. The hero had a ledger ruling at 2.8% alpha, which is the right
 * texture and far too faint to survive a 20px blur.
 *
 * Why threads, and why these threads
 * ----------------------------------
 * The obvious fix is a shader, a particle field or an animated mesh. All of
 * them are the same decision — spend attention on motion — and all of them are
 * wrong here: this runs offline on a workstation with integrated graphics, it
 * will be projected in a lit room, and a police tool that opens with a
 * WebGL light show is telling the wrong story about itself.
 *
 * So the ground is drawn from the product's own grammar instead. These are the
 * same cubic arcs the network diagram uses for a conversation, with horizontal
 * tangents at both ends, sweeping between two implied columns exactly as they
 * do on the dashboard. Someone who signs in recognises the shape. It is a
 * ghost of the actual output rather than an ornament borrowed from a template.
 *
 * One thread is red. In the diagram a red line is a conversation a rule
 * flagged, and it means the same thing here — so even the background obeys the
 * rule that every coloured pixel in this product answers a question. The rest
 * are hairline greys, which is ink, not colour.
 *
 * Nothing here moves, nothing is random at render time, and it costs one
 * rasterised layer. It prints, it projects, and it is identical on every load.
 */

const W = 1600;
const H = 640;

// Fixed, not generated: the same page every time it is opened, and no
// dependency on a random seed that would make two screenshots disagree.
const THREADS = [
  { y1: 0.10, y2: 0.62, o: 0.070 },
  { y1: 0.17, y2: 0.31, o: 0.055 },
  { y1: 0.24, y2: 0.83, o: 0.062 },
  { y1: 0.31, y2: 0.14, o: 0.048 },
  { y1: 0.37, y2: 0.55, o: 0.075 },
  { y1: 0.44, y2: 0.22, o: 0.052 },
  { y1: 0.50, y2: 0.91, o: 0.058 },
  { y1: 0.57, y2: 0.38, o: 0.068 },
  { y1: 0.63, y2: 0.72, o: 0.050 },
  { y1: 0.70, y2: 0.09, o: 0.060 },
  { y1: 0.77, y2: 0.47, o: 0.054 },
  { y1: 0.84, y2: 0.66, o: 0.046 },
  { y1: 0.91, y2: 0.27, o: 0.058 },
];

// The one conversation a rule flagged, drawn the way the diagram draws it.
const FLAGGED = { y1: 0.34, y2: 0.44, o: 0.15 };

const LEFT = W * 0.06;
const RIGHT = W * 0.94;
const REACH = (RIGHT - LEFT) * 0.42;

function arc({ y1, y2 }) {
  const a = y1 * H;
  const b = y2 * H;
  return `M${LEFT},${a} C${LEFT + REACH},${a} ${RIGHT - REACH},${b} ${RIGHT},${b}`;
}

function HeroWeave() {
  const threads = useMemo(
    () => THREADS.map((t) => ({ ...t, d: arc(t) })),
    [],
  );

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="xMidYMid slice"
      // Decoration in the accessibility tree's sense — the meaning it carries
      // is for the eye, and a screen reader announcing thirteen paths would be
      // noise over the heading it sits behind.
      aria-hidden="true"
      focusable="false"
      style={{
        position: 'absolute',
        inset: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        display: 'block',
      }}
    >
      {threads.map((t) => (
        <path
          key={t.d}
          d={t.d}
          fill="none"
          stroke={`rgba(17,19,21,${t.o})`}
          strokeWidth={1}
        />
      ))}
      <path
        d={arc(FLAGGED)}
        fill="none"
        stroke={`rgba(179,38,30,${FLAGGED.o})`}
        strokeWidth={1.4}
      />
      {/* The endpoints, so the threads read as conversations between machines
          rather than as a swoosh. */}
      {[...threads, FLAGGED].map((t, i) => (
        <g key={`e${i}`}>
          <circle cx={LEFT} cy={t.y1 * H} r={3} fill={`rgba(17,19,21,${t.o + 0.03})`} />
          <circle cx={RIGHT} cy={t.y2 * H} r={3} fill={`rgba(17,19,21,${t.o + 0.03})`} />
        </g>
      ))}
    </svg>
  );
}

export default HeroWeave;
