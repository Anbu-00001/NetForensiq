import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Box, Typography, ToggleButton, ToggleButtonGroup } from '@mui/material';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, RULE, RULE_STRONG, PANEL, PANEL_ALT, PAPER,
  CRITICAL, MEDIUM, LOW, HIGH, MONO,
} from '../../theme/tokens';
import { formatBytes } from '../../services/forensics';

/**
 * The capture as a picture — laid out, not simulated.
 *
 * Why this is not a force graph any more
 * --------------------------------------
 * The previous version used d3's force simulation. Two things were wrong with
 * it, and only one of them was cosmetic.
 *
 * The cosmetic one: repulsion pushes nodes wherever there is room, including
 * off the edge of the drawing, so half the diagram ended up outside the box
 * and labels overlapped whatever drifted underneath them.
 *
 * The one that matters: **a force layout is not reproducible.** It is seeded
 * from the node order and settles differently on every render, so the same
 * exhibit produces a different picture each time it is opened. That is fine
 * for exploring and wrong for evidence. An officer who prints this diagram on
 * Tuesday and is asked about it in court in March needs the tool to draw the
 * same thing, and a defence expert given the same capture needs to arrive at
 * the same picture. This layout is a pure function of the data: hosts sorted
 * by severity then volume, ties broken on the address itself. Same evidence,
 * same diagram, every time.
 *
 * What the shape says
 * -------------------
 * The columns are the boundary the investigation actually turns on — inside
 * the monitored network on the left, outside it on the right — so a line
 * crossing the middle is data leaving the organisation, which is the thing an
 * exfiltration case is about. Arrowheads point at whoever *answered*: the
 * host at the tail opened the conversation. "Who called whom" is a fact the
 * flow record holds and a blob of undirected lines throws away.
 *
 * Worst at the top of each column, so reading order matches priority.
 *
 * Reading it without a legend
 * ---------------------------
 * Every circle is on its own row and labelled — labels cannot collide, so
 * nothing is anonymous. Selecting a machine dims everything it did not touch
 * and prints a full sentence underneath; its conversations get their volume
 * written on them. The picture is the index, the sentence is the content.
 *
 * Colour is never the only signal: implicated hosts are ringed, enlarged and
 * carry a printed count, so this survives a colour-blind reader and a
 * projector with the contrast turned down — which is the room it will be
 * shown in.
 */

const RANK_HIGH = 70;
const RANK_MEDIUM = 40;

// Room for the longest address a column can hold, its finding count, and air.
const LABEL_W = 152;
const GUTTER_MIN = 200;
const HEAD_H = 30;
const PAD_TOP = 8;
const PAD_BOTTOM = 10;
// A row can compress to fit more hosts on screen, but not below the point
// where a 10px label stops being legible from the back of a room.
const ROW_MAX = 30;
const ROW_MIN = 17;
const DOT = { min: 3.5, max: 9 };
const AGG_R = 11;
// A monospaced glyph is a known fraction of its point size, which is what
// makes it possible to place a label without measuring the DOM.
const MONO_CH = 0.6;

function dotRadius(node, maxBytes) {
  if (node.aggregate) return AGG_R;
  // Square root, so area rather than diameter tracks volume: a host that moved
  // ten times more data should not be drawn a hundred times larger.
  const share = maxBytes > 0 ? Math.sqrt((node.bytes || 0) / maxBytes) : 0;
  return DOT.min + share * (DOT.max - DOT.min) + (node.finding_count ? 1.5 : 0);
}

function colourFor(node) {
  if (!node) return RULE_STRONG;
  if (node.aggregate) return PANEL_ALT;
  if (node.severity_rank >= RANK_HIGH) return CRITICAL;
  if (node.severity_rank >= RANK_MEDIUM) return MEDIUM;
  return node.internal ? LOW : HIGH;
}

/** Worst first, then busiest, then the address — so the order is total. */
const byGravity = (a, b) => (
  (b.severity_rank - a.severity_rank)
  || (b.finding_count - a.finding_count)
  || ((b.bytes || 0) - (a.bytes || 0))
  || String(a.id).localeCompare(String(b.id))
);

/**
 * Where every circle and line goes. A pure function of (data, width) — no
 * randomness, no animation, no settling.
 */
function buildLayout(data, width, maxHeight) {
  const nodes = data?.nodes ?? [];
  const edges = data?.edges ?? [];
  if (!nodes.length) return null;

  const real = nodes.filter((n) => !n.aggregate);
  const maxBytes = Math.max(1, ...real.map((n) => n.bytes || 0));

  let left = nodes.filter((n) => n.internal && !n.aggregate);
  let right = nodes.filter((n) => !n.internal || n.aggregate);
  let headings = ['Inside the monitored network', 'Outside it'];

  // A capture taken entirely inside one subnet has no boundary to draw, so the
  // division falls back to the other question worth splitting on. If that is
  // also degenerate the hosts go in one column and the lines arc beside it —
  // never an empty column with everything crushed into the other.
  if (!left.length || !right.length) {
    const flagged = nodes.filter((n) => n.finding_count);
    const rest = nodes.filter((n) => !n.finding_count);
    if (flagged.length && rest.length) {
      left = flagged; right = rest;
      headings = ['Implicated', 'Everyone they talked to'];
    } else {
      left = [...nodes]; right = [];
      headings = ['Hosts in this capture', ''];
    }
  }

  left = [...left].sort(byGravity);

  // The right column keeps severity order, but hosts of equal severity are
  // ordered by the average height of what they talked to. That is the
  // barycentre heuristic, and it is the cheapest way to stop the middle of the
  // diagram turning into a cat's cradle without disturbing "worst at the top".
  const leftRow = new Map(left.map((n, i) => [n.id, i]));
  const bary = new Map();
  right.forEach((n) => {
    const rows = edges
      .filter((e) => e.source === n.id || e.target === n.id)
      .map((e) => leftRow.get(e.source === n.id ? e.target : e.source))
      .filter((i) => i !== undefined);
    bary.set(n.id, rows.length
      ? rows.reduce((a, b) => a + b, 0) / rows.length
      : Number.MAX_SAFE_INTEGER);
  });
  right = [...right].sort((a, b) => (
    (b.severity_rank - a.severity_rank)
    || (bary.get(a.id) - bary.get(b.id))
    || byGravity(a, b)
  ));
  // The folded circle is a summary, so it sits under what it summarises.
  right = [...right.filter((n) => !n.aggregate), ...right.filter((n) => n.aggregate)];

  const rows = Math.max(left.length, right.length);
  const usable = maxHeight - HEAD_H - PAD_TOP - PAD_BOTTOM;
  const row = Math.max(ROW_MIN, Math.min(ROW_MAX, rows ? usable / rows : ROW_MAX));
  const svgHeight = Math.round(HEAD_H + PAD_TOP + rows * row + PAD_BOTTOM);

  const single = right.length === 0;
  const leftX = LABEL_W;
  const svgWidth = Math.max(width, LABEL_W * 2 + GUTTER_MIN);
  const rightX = single
    ? leftX + GUTTER_MIN
    : Math.max(leftX + GUTTER_MIN, svgWidth - LABEL_W);
  const gutter = rightX - leftX;

  // Each column is spread across the same height rather than stacked from the
  // top. With one host inside the network talking to sixteen outside — which
  // is what an infected-workstation capture looks like — stacking put the one
  // circle in the top corner and fanned every line downwards off it. Spreading
  // centres it against the peers it is actually talking to, and for two
  // columns of similar length it is indistinguishable from stacking.
  const top = HEAD_H + PAD_TOP;
  const content = rows * row;
  const place = (list, x, side) => list.map((node, i) => ({
    node,
    side,
    x,
    y: top + ((i + 0.5) * content) / list.length,
    r: dotRadius(node, maxBytes),
  }));

  const points = [...place(left, leftX, 'L'), ...place(right, rightX, 'R')];
  const at = new Map(points.map((p) => [p.node.id, p]));

  const drawn = edges
    .map((e) => {
      const a = at.get(e.source);
      const b = at.get(e.target);
      if (!a || !b || a === b) return null;

      let c1x; let c2x;
      if (a.side !== b.side) {
        // Control points offset horizontally, which makes the tangent at both
        // ends horizontal — so an arrowhead lands flat against the circle
        // instead of stabbing it at an angle.
        const reach = gutter * 0.42;
        c1x = a.x + (a.side === 'L' ? reach : -reach);
        c2x = b.x + (b.side === 'L' ? reach : -reach);
      } else {
        // Same column: bow out into the gutter and come back. The further
        // apart the two rows, the wider the bow, so parallel arcs separate.
        const dir = a.side === 'L' ? 1 : -1;
        // Lateral movement between two hosts on the same side of the boundary
        // is a story worth reading, so the arcs are given real room in the
        // middle rather than being pinned against the column. The bow grows
        // with the vertical distance, which is what separates arcs that would
        // otherwise stack on top of each other.
        const bow = Math.min(gutter * 0.42, 46 + Math.abs(a.y - b.y) * 0.55) * dir;
        c1x = a.x + bow;
        c2x = b.x + bow;
      }

      // Stop short of the target circle so the arrowhead touches its edge.
      const heading = Math.sign(b.x - c2x) || 1;
      const endX = b.x - heading * (b.r + 4.5);

      return {
        key: `${e.source}→${e.target}`,
        edge: e,
        a,
        b,
        path: `M${a.x},${a.y} C${c1x},${a.y} ${c2x},${b.y} ${endX},${b.y}`,
        // Cubic midpoint, for hanging the volume on the line when it is picked.
        mid: {
          x: (a.x + 3 * c1x + 3 * c2x + endX) / 8,
          y: (a.y + 3 * a.y + 3 * b.y + b.y) / 8,
        },
      };
    })
    .filter(Boolean);

  return {
    points, edges: drawn, at, headings, single,
    leftX, rightX, svgWidth, svgHeight, row, maxBytes,
  };
}

function NetworkGraph({ data, height = 520, focus, onFocusChange }) {
  const holder = useRef(null);
  const [width, setWidth] = useState(960);
  // Only the address is held. Resolving it against the current data each
  // render means switching session or focus drops a selection that is no
  // longer on screen, with no effect needed to clear it.
  const [selectedId, setSelectedId] = useState(null);
  const [hoverId, setHoverId] = useState(null);

  useLayoutEffect(() => {
    const el = holder.current;
    if (!el) return undefined;
    const measure = () => setWidth(el.clientWidth || 960);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const layout = useMemo(
    () => buildLayout(data, width, height),
    [data, width, height],
  );

  const activeId = hoverId ?? selectedId;
  const selected = useMemo(
    () => data?.nodes?.find((n) => n.id === selectedId) ?? null,
    [data, selectedId],
  );

  // Which hosts the active one actually spoke to. Used to dim the rest, so
  // picking a machine answers "and who did it talk to" without reading a table.
  const neighbours = useMemo(() => {
    if (!activeId || !layout) return null;
    const set = new Set([activeId]);
    layout.edges.forEach(({ edge }) => {
      if (edge.source === activeId) set.add(edge.target);
      if (edge.target === activeId) set.add(edge.source);
    });
    return set;
  }, [activeId, layout]);

  if (!layout) {
    return (
      <Typography sx={{ fontSize: 13, color: GREY, py: 4 }}>
        No conversations to draw for this capture.
      </Typography>
    );
  }

  const { points, edges, headings, single, leftX, rightX, svgWidth, svgHeight } = layout;

  return (
    <Box>
      {/*
        The point of the diagram, in a sentence, above the diagram. A reader who
        looks at nothing else has still been told the finding.
      */}
      <Box sx={{
        display: 'flex', alignItems: 'flex-start', gap: 2, mb: 1.5, flexWrap: 'wrap',
      }}>
        <Typography sx={{
          flexGrow: 1, minWidth: 260, fontSize: 14.5, lineHeight: 1.5,
          color: INK, fontWeight: 600,
          borderLeft: `3px solid ${CRITICAL}`, pl: 1.5,
        }}>
          {data.headline}
        </Typography>

        {onFocusChange && (
          <ToggleButtonGroup
            size="small" exclusive value={focus}
            onChange={(_e, next) => next && onFocusChange(next)}
            sx={{
              '& .MuiToggleButton-root': {
                fontSize: 11, py: 0.35, px: 1.2, textTransform: 'none',
                color: GREY, borderColor: RULE,
                '&.Mui-selected': {
                  color: PAPER, backgroundColor: INK,
                  '&:hover': { backgroundColor: INK_SOFT },
                },
              },
            }}
          >
            <ToggleButton value="flagged">Implicated only</ToggleButton>
            <ToggleButton value="all">Every host</ToggleButton>
          </ToggleButtonGroup>
        )}
      </Box>

      <Box
        ref={holder}
        sx={{ overflowX: 'auto', border: `1px solid ${RULE}`, borderRadius: 1, backgroundColor: PAPER }}
      >
        <svg
          width={svgWidth}
          height={svgHeight}
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          role="img"
          aria-label={`Network diagram. ${data.headline}`}
          style={{ display: 'block' }}
          onMouseLeave={() => setHoverId(null)}
        >
          <defs>
            {[['nf-arrow-plain', RULE_STRONG], ['nf-arrow-risk', CRITICAL]].map(([id, fill]) => (
              <marker
                key={id} id={id} viewBox="0 0 8 8" refX="7" refY="4"
                markerWidth="7" markerHeight="7" orient="auto-start-reverse"
              >
                <path d="M0,1 L7,4 L0,7 z" fill={fill} />
              </marker>
            ))}
          </defs>

          {/* Column headings, and the axis each column of circles sits on. The
              rule is what makes a row scannable across the width. */}
          {/* Anchored to the outer edge, not to the column axis: the axis is
              only LABEL_W from the edge and "INSIDE THE MONITORED NETWORK" is
              wider than that, so right-aligning it ran the first words off the
              drawing. */}
          <text
            x={2} y={16} textAnchor="start"
            fontSize={9.5} fontFamily={MONO} fill={GREY_MUTED}
            letterSpacing="0.08em"
          >
            {headings[0].toUpperCase()}
          </text>
          <line x1={leftX} y1={HEAD_H - 8} x2={leftX} y2={svgHeight - 4}
            stroke={RULE} strokeWidth={1} />
          {!single && (
            <>
              <text
                x={svgWidth - 2} y={16} textAnchor="end"
                fontSize={9.5} fontFamily={MONO} fill={GREY_MUTED}
                letterSpacing="0.08em"
              >
                {headings[1].toUpperCase()}
              </text>
              <line x1={rightX} y1={HEAD_H - 8} x2={rightX} y2={svgHeight - 4}
                stroke={RULE} strokeWidth={1} />
            </>
          )}

          {/* Conversations. Flagged ones are drawn last so they sit on top of
              the ordinary traffic rather than under it. */}
          <g fill="none">
            {[...edges].sort((p, q) => (p.edge.risk > 0 ? 1 : 0) - (q.edge.risk > 0 ? 1 : 0))
              .map(({ key, edge, path }) => {
                const risky = edge.risk > 0;
                const touches = !activeId
                  || edge.source === activeId || edge.target === activeId;
                return (
                  <path
                    key={key}
                    d={path}
                    stroke={risky ? CRITICAL : RULE_STRONG}
                    strokeWidth={touches && activeId ? 2 : (risky ? 1.5 : 1)}
                    strokeDasharray={edge.to_aggregate ? '3 3' : undefined}
                    markerEnd={`url(#${risky ? 'nf-arrow-risk' : 'nf-arrow-plain'})`}
                    opacity={touches ? (risky ? 0.85 : 0.55) : 0.08}
                  />
                );
              })}
          </g>

          {/* What the picked host moved, written on the line rather than
              hidden in a tooltip nobody hovers long enough to read. */}
          {activeId && edges
            .filter(({ edge }) => edge.source === activeId || edge.target === activeId)
            .map(({ key, edge, mid }) => {
              const text = `${formatBytes(edge.bytes)} · ${edge.flows} conv`;
              const w = text.length * 9 * MONO_CH + 8;
              return (
                <g key={`lbl-${key}`} pointerEvents="none">
                  <rect
                    x={mid.x - w / 2} y={mid.y - 8} width={w} height={14} rx={2}
                    fill={PAPER} stroke={RULE} strokeWidth={0.75}
                  />
                  <text
                    x={mid.x} y={mid.y + 2.5} textAnchor="middle"
                    fontSize={9} fontFamily={MONO} fill={INK_SOFT}
                  >
                    {text}
                  </text>
                </g>
              );
            })}

          {/* The machines. */}
          {points.map(({ node, side, x, y, r }) => {
            const lit = !neighbours || neighbours.has(node.id);
            const anchor = side === 'L' && !single ? 'end' : 'start';
            const labelX = anchor === 'end' ? x - r - 7 : x + r + 7;
            const count = node.finding_count
              ? `${node.finding_count} ` : '';
            return (
              <g
                key={node.id}
                opacity={lit ? 1 : 0.22}
                style={{ cursor: 'pointer' }}
                onClick={() => setSelectedId(
                  (prev) => (prev === node.id ? null : node.id),
                )}
                onMouseEnter={() => setHoverId(node.id)}
              >
                <title>{`${node.label ?? node.id}\n${node.caption}`}</title>
                {/* A generous invisible target: the circles are small on
                    purpose and a 4px hit area is unusable with a trackpad. */}
                <rect
                  x={anchor === 'end' ? x - LABEL_W : x - r - 4}
                  y={y - layout.row / 2}
                  width={LABEL_W + r + 4} height={layout.row}
                  fill="transparent"
                />
                <circle
                  cx={x} cy={y} r={r}
                  fill={colourFor(node)}
                  fillOpacity={node.aggregate ? 1 : 0.92}
                  stroke={node.aggregate
                    ? GREY_MUTED
                    : (node.finding_count ? INK : 'rgba(17,19,21,0.28)')}
                  strokeWidth={node.finding_count ? 1.8 : 1}
                  strokeDasharray={node.aggregate ? '4 3' : undefined}
                />
                {node.aggregate && (
                  <text
                    x={x} y={y + 3.5} textAnchor="middle"
                    fontSize={10} fontWeight={700} fontFamily={MONO}
                    fill={INK_SOFT} pointerEvents="none"
                  >
                    {node.collapsed_count}
                  </text>
                )}
                {selectedId === node.id && (
                  <circle
                    cx={x} cy={y} r={r + 4.5} fill="none"
                    stroke={INK} strokeWidth={1} strokeOpacity={0.55}
                  />
                )}
                <text
                  x={labelX} y={y + 3.2} textAnchor={anchor}
                  fontSize={10} fontFamily={MONO} pointerEvents="none"
                  fill={node.finding_count ? INK : GREY}
                  fontWeight={node.finding_count ? 600 : 400}
                >
                  {anchor === 'start' && count
                    && <tspan fill={colourFor(node)} fontWeight={700}>{count}</tspan>}
                  <tspan>{node.aggregate ? 'other hosts' : node.id}</tspan>
                  {anchor === 'end' && count
                    && <tspan fill={colourFor(node)} fontWeight={700}>{` ${node.finding_count}`}</tspan>}
                </text>
              </g>
            );
          })}
        </svg>
      </Box>

      {/* The sentence, not a legend. */}
      <Box sx={{
        mt: 1, p: 1.5, minHeight: 54,
        borderLeft: `3px solid ${selected ? colourFor(selected) : RULE_STRONG}`,
        backgroundColor: PANEL,
      }}>
        {selected ? (
          <>
            <Typography sx={{
              fontSize: 12.5, fontFamily: MONO, color: INK, mb: 0.4, fontWeight: 600,
            }}>
              {selected.label ?? selected.id}
            </Typography>
            <Typography sx={{ fontSize: 12.5, color: INK_SOFT }}>
              {selected.caption}
            </Typography>
          </>
        ) : (
          <Typography sx={{ fontSize: 12.5, color: GREY }}>
            Point at any machine to see only what it touched; click to keep it.
            An arrow points at whoever answered — the machine at the tail opened
            the conversation. The number beside an address is how many findings
            are recorded against it, larger circles moved more data, and the
            dashed circle stands for the hosts with nothing flagged.
          </Typography>
        )}
      </Box>

      <Typography sx={{ fontSize: 11.5, color: GREY_MUTED, mt: 0.8 }}>
        {data.caption}
        {data.home_networks ? ` · monitored network: ${data.home_networks}` : ''}
        {' · '}
        laid out by severity, not by simulation, so the same capture always
        draws the same diagram.
      </Typography>
    </Box>
  );
}

export default NetworkGraph;
