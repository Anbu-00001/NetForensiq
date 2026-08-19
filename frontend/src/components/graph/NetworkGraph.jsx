import { useEffect, useMemo, useRef, useState } from 'react';
import { Box, Typography, ToggleButton, ToggleButtonGroup } from '@mui/material';
import * as d3 from 'd3';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, RULE, RULE_STRONG, PANEL, PAPER,
  CRITICAL, MEDIUM, LOW, HIGH, MONO,
} from '../../theme/tokens';

/**
 * The capture as a picture.
 *
 * The problem this had
 * --------------------
 * Fifty-one circles and eighty lines, drawn faithfully, produce a diagram
 * whose only readable message is "there was a network". Everything that
 * mattered — the fifteen implicated machines, and which one is worst — was in
 * there and invisible.
 *
 * So the server now folds the quiet hosts into a single circle and keeps the
 * conversations that carry a finding plus each host's busiest links. This
 * component's job is to make the remaining picture answer a question before it
 * is asked, which is what the headline above the diagram is for. A reader who
 * looks at nothing else has still been told the finding.
 *
 * Reading it without a legend
 * ---------------------------
 * A legend is a lookup table the reader holds in their head. Instead: every
 * circle is labelled, implicated ones are ringed and larger, and selecting any
 * of them prints a full sentence underneath. The picture is the index; the
 * sentence is the content.
 *
 * Colour is never the only signal — implicated hosts are ringed and enlarged
 * too, so the diagram survives a colour-blind reader and a projector with the
 * contrast turned down, which is the room this will be shown in.
 */

const RANK_HIGH = 70;
const RANK_MEDIUM = 40;

const SIZE = { min: 4, max: 20 };

function radius(node, maxBytes) {
  if (node.aggregate) return 22;
  // Square root, so area rather than diameter tracks volume: a host that moved
  // ten times more data should not be drawn a hundred times larger.
  const share = maxBytes > 0 ? Math.sqrt(node.bytes / maxBytes) : 0;
  const base = SIZE.min + share * (SIZE.max - SIZE.min);
  return node.finding_count ? base + 3 : base;
}

function colourFor(node) {
  if (node.aggregate) return PANEL;
  if (node.severity_rank >= RANK_HIGH) return CRITICAL;
  if (node.severity_rank >= RANK_MEDIUM) return MEDIUM;
  return node.internal ? LOW : HIGH;
}

function NetworkGraph({ data, height = 360, focus, onFocusChange }) {
  const svgRef = useRef(null);
  // Only the address is held. Resolving it against the current data each
  // render means switching session or focus drops a selection that is no
  // longer on screen, with no effect needed to clear it.
  const [selectedId, setSelectedId] = useState(null);
  const selected = useMemo(
    () => data?.nodes?.find((n) => n.id === selectedId) ?? null,
    [data, selectedId],
  );

  const maxBytes = useMemo(
    () => d3.max((data?.nodes ?? []).filter((n) => !n.aggregate), (n) => n.bytes) || 1,
    [data],
  );

  useEffect(() => {
    if (!data?.nodes?.length || !svgRef.current) return undefined;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = svgRef.current.clientWidth || 800;
    const nodes = data.nodes.map((n) => ({ ...n }));
    const links = data.edges.map((e) => ({ ...e }));

    // Repulsion scaled to the space and the population. A fixed strength packs
    // sixty hosts into an unreadable blob on a wide screen and draws seventeen
    // as a tight knot in an empty panel.
    const spread = Math.max(width, height) / Math.sqrt(nodes.length + 1);
    const charge = Math.min(700, Math.max(220, spread * 11));

    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d) => d.id)
        .distance((d) => (d.to_aggregate ? 90 : Math.min(110, spread * 1.2)))
        .strength(0.3))
      .force('charge', d3.forceManyBody().strength(-charge))
      .force('x', d3.forceX(width / 2).strength(0.06))
      .force('y', d3.forceY(height / 2).strength(0.1))
      .force('collide', d3.forceCollide().radius((d) => radius(d, maxBytes) + 9));

    const link = svg.append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', (d) => (d.risk > 0 ? CRITICAL : RULE_STRONG))
      .attr('stroke-opacity', (d) => (d.risk > 0 ? 0.75 : 0.5))
      .attr('stroke-width', (d) => (d.risk > 0 ? 1.6 : 0.9))
      // A folded-away edge is a summary of many, so it is drawn as one.
      .attr('stroke-dasharray', (d) => (d.to_aggregate ? '3 3' : null));

    const node = svg.append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .style('cursor', 'pointer')
      .on('click', (_event, d) => setSelectedId(d.id));

    node.append('circle')
      .attr('r', (d) => radius(d, maxBytes))
      .attr('fill', (d) => colourFor(d))
      .attr('fill-opacity', (d) => (d.aggregate ? 1 : 0.9))
      // The ring is the second signal: an implicated host is identifiable
      // without relying on hue.
      .attr('stroke', (d) => {
        if (d.aggregate) return GREY_MUTED;
        return d.finding_count ? INK : 'rgba(17,19,21,0.25)';
      })
      .attr('stroke-width', (d) => (d.finding_count ? 2 : 1))
      .attr('stroke-dasharray', (d) => (d.aggregate ? '4 3' : null));

    // The count sits inside the folded circle, so it reads as a quantity
    // rather than as one more machine.
    node.filter((d) => d.aggregate)
      .append('text')
      .text((d) => d.collapsed_count)
      .attr('text-anchor', 'middle')
      .attr('dy', 4)
      .attr('font-size', 12)
      .attr('font-weight', 700)
      .attr('font-family', MONO)
      .attr('fill', INK_SOFT)
      .attr('pointer-events', 'none');

    node.append('title').text((d) => `${d.label ?? d.id}\n${d.caption}`);

    // Labelled: everything implicated, the folded circle, and anything big
    // enough that leaving it anonymous would be odd.
    const label = svg.append('g')
      .selectAll('text')
      .data(nodes.filter((n) => n.finding_count || n.aggregate
        || n.bytes > maxBytes * 0.12))
      .join('text')
      .text((d) => (d.aggregate ? 'others' : d.id))
      .attr('font-size', 9)
      .attr('font-family', MONO)
      .attr('fill', (d) => (d.finding_count ? INK : GREY))
      .attr('font-weight', (d) => (d.finding_count ? 600 : 400))
      .attr('text-anchor', 'middle')
      .attr('pointer-events', 'none');

    simulation.on('tick', () => {
      link
        .attr('x1', (d) => d.source.x).attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x).attr('y2', (d) => d.target.y);
      node.attr('transform', (d) => `translate(${d.x},${d.y})`);
      label
        .attr('x', (d) => d.x)
        .attr('y', (d) => d.y - radius(d, maxBytes) - 4);
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
  }, [data, height, maxBytes]);

  if (!data?.nodes?.length) {
    return (
      <Typography sx={{ fontSize: 13, color: GREY, py: 4 }}>
        No conversations to draw for this capture.
      </Typography>
    );
  }

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

      <Box sx={{ overflowX: 'auto', border: `1px solid ${RULE}`, borderRadius: 1 }}>
        <svg
          ref={svgRef}
          width="100%"
          height={height}
          role="img"
          aria-label={`Network diagram. ${data.headline}`}
          style={{ display: 'block', minWidth: 320, background: PAPER }}
        />
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
            Select any machine to read what it did. Larger circles moved more
            data; ringed circles have findings recorded against them. The dashed
            circle stands for hosts with nothing flagged.
          </Typography>
        )}
      </Box>

      <Typography sx={{ fontSize: 11.5, color: GREY_MUTED, mt: 0.8 }}>
        {data.caption}
        {data.home_networks ? ` · monitored network: ${data.home_networks}` : ''}
      </Typography>
    </Box>
  );
}

export default NetworkGraph;
