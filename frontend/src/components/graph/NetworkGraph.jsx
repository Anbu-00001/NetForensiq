import { useEffect, useMemo, useRef, useState } from 'react';
import { Box, Typography } from '@mui/material';
import * as d3 from 'd3';

/**
 * The capture as a picture.
 *
 * Why this exists
 * ---------------
 * The dashboard's figures answer "how much traffic was there". An officer asks
 * a different question — "which machine is in trouble, and who was it talking
 * to" — and that is a shape, not a number. A table of 166,093 flows cannot be
 * read; a diagram with the compromised host at the centre can be read in a
 * second, by someone who has never heard of a flow.
 *
 * Reading it without a legend
 * ---------------------------
 * A legend is a lookup table the reader has to hold in their head. Instead:
 * every circle is labelled with its address, the flagged ones are ringed and
 * carry a finding count, and selecting any of them prints a full sentence
 * about that machine underneath. The picture is the index; the sentence is the
 * content.
 *
 * Colour is never the only signal — flagged hosts are also ringed and larger,
 * so the diagram survives a colour-blind reader and a projector with the
 * contrast turned down, which is the room this will actually be shown in.
 */

// Severity ranks as the backend weights them. Above HIGH a host is drawn as
// implicated rather than merely busy.
const RANK_HIGH = 70;
const RANK_MEDIUM = 40;

const SIZE = { min: 5, max: 26 };

function radius(node, maxBytes) {
  // Square root, so area rather than diameter tracks volume: a host that moved
  // ten times more data should not be drawn a hundred times larger.
  const share = maxBytes > 0 ? Math.sqrt(node.bytes / maxBytes) : 0;
  const base = SIZE.min + share * (SIZE.max - SIZE.min);
  return node.finding_count ? base + 3 : base;
}

function colourFor(node, palette) {
  if (node.severity_rank >= RANK_HIGH) return palette.hostile;
  if (node.severity_rank >= RANK_MEDIUM) return palette.medium;
  return node.internal ? palette.internal : palette.external;
}

function NetworkGraph({ data, height = 420 }) {
  const svgRef = useRef(null);
  const [selected, setSelected] = useState(null);

  const palette = useMemo(() => ({
    internal: '#5B8DEF',
    external: '#FF9933',
    medium: '#E8C24A',
    hostile: '#FF6B6B',
    edge: 'rgba(167,176,196,0.22)',
    edgeRisk: 'rgba(255,107,107,0.55)',
    label: '#A7B0C4',
  }), []);

  useEffect(() => {
    if (!data?.nodes?.length || !svgRef.current) return undefined;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = svgRef.current.clientWidth || 800;
    const maxBytes = d3.max(data.nodes, (n) => n.bytes) || 1;

    // d3's simulation mutates the objects it is given. Copying first keeps the
    // component's props immutable, so a re-render does not inherit positions
    // from the previous layout and jump.
    const nodes = data.nodes.map((n) => ({ ...n }));
    const links = data.edges.map((e) => ({ ...e }));

    // Repulsion is scaled to the space available and to how many hosts there
    // are. A fixed strength packs 60 hosts into an unreadable blob on a wide
    // screen, and draws 17 hosts as a tight knot in the middle of an empty
    // panel — technically a layout, but it wastes the space the picture is for.
    //
    // forceX/forceY replace forceCenter: `center` translates the whole layout
    // to the middle without spreading it, so the cluster stays as tight as the
    // charge left it.
    const spread = Math.max(width, height) / Math.sqrt(nodes.length + 1);
    const charge = Math.min(900, Math.max(280, spread * 14));

    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d) => d.id)
        .distance(Math.min(150, spread * 1.5)).strength(0.25))
      .force('charge', d3.forceManyBody().strength(-charge))
      .force('x', d3.forceX(width / 2).strength(0.05))
      .force('y', d3.forceY(height / 2).strength(0.08))
      .force('collide', d3.forceCollide().radius((d) => radius(d, maxBytes) + 10));

    const link = svg.append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', (d) => (d.risk > 0 ? palette.edgeRisk : palette.edge))
      .attr('stroke-width', (d) => (d.risk > 0 ? 1.8 : 1));

    const node = svg.append('g')
      .selectAll('circle')
      .data(nodes)
      .join('circle')
      .attr('r', (d) => radius(d, maxBytes))
      .attr('fill', (d) => colourFor(d, palette))
      .attr('fill-opacity', 0.85)
      // The ring is the second signal: a flagged host is identifiable without
      // relying on hue.
      .attr('stroke', (d) => (d.finding_count ? '#FFFFFF' : 'rgba(0,0,0,0.35)'))
      .attr('stroke-width', (d) => (d.finding_count ? 2 : 1))
      .style('cursor', 'pointer')
      .on('click', (_event, d) => setSelected(d));

    // Native tooltip as well as the caption panel, so the information is
    // reachable by hover and by keyboard focus, not only by clicking.
    node.append('title').text((d) => `${d.id}\n${d.caption}`);

    const label = svg.append('g')
      .selectAll('text')
      .data(nodes.filter((n) => n.finding_count || n.bytes > maxBytes * 0.08))
      .join('text')
      .text((d) => d.id)
      .attr('font-size', 9.5)
      .attr('font-family', "'JetBrains Mono', monospace")
      .attr('fill', palette.label)
      .attr('text-anchor', 'middle')
      .attr('pointer-events', 'none');

    simulation.on('tick', () => {
      link
        .attr('x1', (d) => d.source.x).attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x).attr('y2', (d) => d.target.y);
      node.attr('cx', (d) => d.x).attr('cy', (d) => d.y);
      label
        .attr('x', (d) => d.x)
        .attr('y', (d) => d.y - radius(d, maxBytes) - 5);
    });

    node.call(d3.drag()
      .on('start', (event, d) => {
        if (!event.active) simulation.alphaTarget(0.25).restart();
        d.fx = d.x; d.fy = d.y;
      })
      .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on('end', (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null; d.fy = null;
      }));

    // The simulation runs on a timer; without this it keeps running after the
    // component is gone and holds the whole node array alive with it.
    return () => simulation.stop();
  }, [data, height, palette]);

  if (!data?.nodes?.length) {
    return (
      <Typography sx={{ fontSize: 13, color: 'rgba(232,236,244,0.6)', py: 4 }}>
        No conversations to draw for this capture.
      </Typography>
    );
  }

  return (
    <Box>
      <Box sx={{ overflowX: 'auto' }}>
        <svg
          ref={svgRef}
          width="100%"
          height={height}
          role="img"
          aria-label={`Network diagram: ${data.caption}`}
          style={{ display: 'block', minWidth: 320 }}
        />
      </Box>

      {/* The sentence, not a legend. */}
      <Box sx={{
        mt: 1, p: 1.5, minHeight: 58,
        borderLeft: `3px solid ${selected ? colourFor(selected, palette) : 'rgba(167,176,196,0.3)'}`,
        backgroundColor: 'rgba(255,255,255,0.03)',
      }}>
        {selected ? (
          <>
            <Typography sx={{
              fontSize: 12.5, fontFamily: "'JetBrains Mono', monospace",
              color: '#E8ECF4', mb: 0.4,
            }}>
              {selected.id}
            </Typography>
            <Typography sx={{ fontSize: 12.5, color: 'rgba(232,236,244,0.82)' }}>
              {selected.caption}
            </Typography>
          </>
        ) : (
          <Typography sx={{ fontSize: 12.5, color: 'rgba(232,236,244,0.7)' }}>
            Select any machine to read what it did. Larger circles moved more
            data; ringed circles have findings recorded against them.
          </Typography>
        )}
      </Box>

      <Typography sx={{ fontSize: 11.5, color: 'rgba(232,236,244,0.6)', mt: 0.8 }}>
        {data.caption}
        {data.home_networks ? ` · monitored network: ${data.home_networks}` : ''}
      </Typography>
    </Box>
  );
}

export default NetworkGraph;
