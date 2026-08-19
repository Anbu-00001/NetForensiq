import { useMemo, useState } from 'react';
import { Box, Typography } from '@mui/material';

/**
 * Who talked to whom, drawn.
 *
 * The functional requirements ask for "graph-based visualization of network
 * communication" and "highlighting suspicious nodes and connections". This is
 * that, and it is also the answer to a fairer complaint: a bar chart labelled
 * "Flows 166,972" tells an investigating officer nothing, while a picture of
 * four outside machines all pointing at one server tells them what happened
 * before anyone explains it.
 *
 * Why the layout is fixed rather than force-directed
 * --------------------------------------------------
 * A force simulation settles somewhere slightly different every run, so the
 * same capture draws a different picture each time it is opened — which is a
 * poor property for something that may be printed and put in a case file, and
 * a worse one for a demonstration. The layout here is deterministic: the
 * machine with the most findings sits at the centre, everything it spoke to is
 * placed around it in a stable order, and the same data always produces the
 * same diagram.
 *
 * What the drawing does and does not assert
 * -----------------------------------------
 * A red edge means one of its two endpoints was named by a rule. It does not
 * mean the *link* was found malicious — the rules name machines, not lines.
 * The legend says so, because a diagram that implies a stronger conclusion
 * than the evidence supports is worse than no diagram.
 */

const SIZE = 560;
const CENTRE = SIZE / 2;
const RADIUS = SIZE * 0.36;

// Node radius. Scaled by the square root of conversation count so that area,
// not radius, tracks volume — a circle drawn with radius proportional to a
// count exaggerates large values by squaring them.
const MIN_R = 9;
const MAX_R = 26;

function radiusFor(flows, busiest) {
  if (!busiest) return MIN_R;
  return MIN_R + (MAX_R - MIN_R) * Math.sqrt(flows / busiest);
}

// Edge thickness by log of bytes: a one-week capture spans six orders of
// magnitude, and a linear scale renders everything except the largest link as
// an invisible hairline.
function strokeFor(bytes, heaviest) {
  if (!heaviest || bytes <= 0) return 1;
  return 1 + 3.5 * (Math.log10(bytes + 1) / Math.log10(heaviest + 1));
}

const COLOURS = {
  flagged: '#FF6B6B',
  internal: '#5B8DEF',
  external: '#FF9933',
  quiet: 'rgba(167,176,196,0.55)',
};

function colourFor(host) {
  if (host.finding_count) return COLOURS.flagged;
  return host.is_internal ? COLOURS.internal : COLOURS.external;
}

function LinkChart({ hosts = [], edges = [], totalHosts = 0 }) {
  const [focus, setFocus] = useState(null);

  const layout = useMemo(() => {
    if (!hosts.length) return { nodes: [], byIp: {} };

    // The centre is the machine the capture is about: most rules first, then
    // most conversations. Ties broken by IP so the choice is reproducible.
    const ranked = [...hosts].sort((a, b) =>
      (b.distinct_rules?.length ?? 0) - (a.distinct_rules?.length ?? 0)
      || b.flow_count - a.flow_count
      || a.ip.localeCompare(b.ip));

    const [hub, ...rest] = ranked;
    const busiest = Math.max(...hosts.map((h) => h.flow_count), 1);

    const nodes = [{
      ...hub, x: CENTRE, y: CENTRE, r: radiusFor(hub.flow_count, busiest), isHub: true,
    }];

    // Placed on a circle in rank order, starting at the top and going
    // clockwise. Stable for a given set of hosts.
    rest.forEach((host, i) => {
      const angle = (i / rest.length) * 2 * Math.PI - Math.PI / 2;
      nodes.push({
        ...host,
        x: CENTRE + RADIUS * Math.cos(angle),
        y: CENTRE + RADIUS * Math.sin(angle),
        r: radiusFor(host.flow_count, busiest),
        isHub: false,
      });
    });

    const byIp = Object.fromEntries(nodes.map((n) => [n.ip, n]));
    return { nodes, byIp };
  }, [hosts]);

  const heaviest = useMemo(
    () => Math.max(...edges.map((e) => e.bytes), 1), [edges],
  );

  if (!hosts.length) {
    return (
      <Box sx={{ p: 3, textAlign: 'center', color: 'rgba(167,176,196,0.9)' }}>
        <Typography sx={{ fontSize: 13 }}>
          No machines to draw yet — run detection on a capture first.
        </Typography>
      </Box>
    );
  }

  const shown = layout.nodes.length;
  const selected = focus ? layout.byIp[focus] : null;

  return (
    <Box>
      <Typography sx={{ fontSize: 13, color: '#E8ECF4', mb: 0.25 }}>
        Who talked to whom
      </Typography>
      <Typography sx={{ fontSize: 11.5, color: 'rgba(167,176,196,0.95)', mb: 1.5 }}>
        {shown} of {totalHosts.toLocaleString()} machines — the ones a rule
        named, and everything they spoke to. Circle area is how many
        conversations; line thickness is how much data moved.
      </Typography>

      <Box sx={{ overflowX: 'auto' }}>
        <svg
          viewBox={`0 0 ${SIZE} ${SIZE}`}
          width="100%"
          style={{ maxWidth: SIZE, display: 'block', margin: '0 auto' }}
          role="img"
          aria-label={
            `Communication diagram: ${shown} machines, ${edges.length} links. `
            + layout.nodes
              .filter((n) => n.finding_count)
              .map((n) => `${n.ip} flagged by ${n.distinct_rules.length} rules`)
              .join('; ')
          }
        >
          <g>
            {edges.map((edge) => {
              const a = layout.byIp[edge.source];
              const b = layout.byIp[edge.target];
              if (!a || !b) return null;
              const dim = focus && edge.source !== focus && edge.target !== focus;
              return (
                <line
                  key={`${edge.source}-${edge.target}`}
                  x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                  stroke={edge.touches_finding ? COLOURS.flagged : COLOURS.quiet}
                  strokeWidth={strokeFor(edge.bytes, heaviest)}
                  strokeOpacity={dim ? 0.12 : 0.75}
                />
              );
            })}
          </g>

          <g>
            {layout.nodes.map((node) => {
              const dim = focus && node.ip !== focus
                && !edges.some((e) =>
                  (e.source === focus && e.target === node.ip)
                  || (e.target === focus && e.source === node.ip));
              return (
                <g
                  key={node.ip}
                  opacity={dim ? 0.25 : 1}
                  onMouseEnter={() => setFocus(node.ip)}
                  onMouseLeave={() => setFocus(null)}
                  style={{ cursor: 'pointer' }}
                >
                  <circle
                    cx={node.x} cy={node.y} r={node.r}
                    fill={colourFor(node)}
                    fillOpacity={node.finding_count ? 0.9 : 0.55}
                    stroke={colourFor(node)}
                    strokeWidth={node.isHub ? 2.5 : 1.25}
                  />
                  <text
                    x={node.x}
                    y={node.y + node.r + 13}
                    textAnchor="middle"
                    fill="#E8ECF4"
                    style={{ fontSize: 10.5, fontFamily: "'JetBrains Mono', monospace" }}
                  >
                    {node.ip}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
      </Box>

      {/* Named in words, not by colour alone: colour is not information a
          colour-blind reader can use, and this diagram may be printed. */}
      <Box sx={{
        display: 'flex', gap: 2, flexWrap: 'wrap', mt: 1,
        fontSize: 11.5, color: 'rgba(167,176,196,0.95)',
      }}>
        {[['Named by a rule', COLOURS.flagged],
          ['Inside the monitored network', COLOURS.internal],
          ['Outside it', COLOURS.external]].map(([label, colour]) => (
            <Box key={label} sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
              <Box component="span" sx={{
                width: 9, height: 9, borderRadius: '50%', backgroundColor: colour,
              }} />
              {label}
            </Box>
        ))}
      </Box>

      <Typography sx={{ fontSize: 11, color: 'rgba(167,176,196,0.85)', mt: 1 }}>
        A red line means one of the two machines it joins was named by a rule.
        The rules name machines, not links — the line is drawn red to point the
        eye, not to conclude anything about the connection itself.
      </Typography>

      {selected && (
        <Box sx={{
          mt: 1.5, p: 1.5, border: '1px solid rgba(167,176,196,0.16)',
          borderRadius: 1, backgroundColor: 'rgba(255,255,255,0.02)',
        }}>
          <Typography sx={{
            fontSize: 12.5, fontFamily: "'JetBrains Mono', monospace", color: '#E8ECF4',
          }}>
            {selected.ip} · {selected.role}
          </Typography>
          <Typography sx={{ fontSize: 12, color: 'rgba(167,176,196,0.95)', mt: 0.5 }}>
            {selected.verdict}
          </Typography>
        </Box>
      )}
    </Box>
  );
}

export default LinkChart;
