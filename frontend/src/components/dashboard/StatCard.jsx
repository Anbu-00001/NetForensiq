import { Box, Typography } from '@mui/material';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, RULE, PAPER, MONO,
} from '../../theme/tokens';

/**
 * One figure, with the shape behind it.
 *
 * Why every card now carries a chart
 * ----------------------------------
 * "DNS queries 320" is a fact an officer cannot act on. Three hundred and
 * twenty lookups is either completely normal or the whole case, and the number
 * alone does not say which. The breakdown does: five names, one of them
 * queried two hundred times, is a different screen entirely.
 *
 * So each card shows the figure *and* the distribution behind it, chosen per
 * card to be the dimension that changes what you would do next:
 *
 *   packets, flows, flagged   over time      — when did it happen
 *   DNS queries               by name        — what was it looking for
 *   findings                  by severity    — how bad
 *
 * Nothing is drawn from invented data. A card with no series renders the
 * figure alone rather than a plausible-looking line, because a sparkline
 * beside a real number implies a history the capture may not contain.
 */

function Spark({ series, colour }) {
  const max = Math.max(...series.map((p) => p.value), 1);
  return (
    <Box sx={{ display: 'flex', alignItems: 'flex-end', gap: '1px', height: 30, mt: 1.2 }}>
      {series.map((point, i) => (
        <Box
          key={i}
          title={point.label}
          sx={{
            flex: 1,
            // '1px', not 1. MUI's sizing system reads a bare number <= 1 on a
            // width prop as a fraction, so `minWidth: 1` asked every bar for
            // 100% of the card and the sparklines ran across the whole page.
            minWidth: '1px',
            // A zero bucket still gets a hairline, so a gap in the traffic is
            // visibly a gap rather than the chart having ended.
            height: `${Math.max((point.value / max) * 100, point.value ? 8 : 0)}%`,
            // A quiet bucket keeps a hairline so the axis stays continuous —
            // a gap in the traffic should read as a gap, not as the chart
            // having stopped.
            minHeight: '1.5px',
            backgroundColor: point.value ? colour : RULE,
            opacity: point.value ? 0.85 : 1,
          }}
        />
      ))}
    </Box>
  );
}

function Bars({ series, colour }) {
  const max = Math.max(...series.map((p) => p.value), 1);
  return (
    <Box sx={{ mt: 1.2 }}>
      {series.map((point) => (
        <Box key={point.label} sx={{ mb: 0.5 }}>
          <Box sx={{
            display: 'flex', justifyContent: 'space-between', gap: 1, mb: '2px',
          }}>
            <Typography
              title={point.label}
              sx={{
                fontSize: 10, fontFamily: MONO, color: GREY,
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}
            >
              {point.label}
            </Typography>
            <Typography sx={{ fontSize: 10, fontFamily: MONO, color: INK_SOFT, flexShrink: 0 }}>
              {point.value}
            </Typography>
          </Box>
          <Box sx={{ height: 3, backgroundColor: RULE }}>
            <Box sx={{
              height: '100%',
              width: `${Math.max((point.value / max) * 100, 2)}%`,
              backgroundColor: point.colour ?? colour,
            }} />
          </Box>
        </Box>
      ))}
    </Box>
  );
}

function StatCard({ title, primary, secondary, color, chart, caption }) {
  const series = chart?.series?.length ? chart.series : null;

  return (
    <Box
      sx={{
        flex: 1,
        minWidth: 178,
        p: 1.8,
        borderRadius: 1,
        backgroundColor: PAPER,
        border: `1px solid ${RULE}`,
        // The measure's own colour, as a rule down the left edge. Enough to
        // tell five cards apart at a glance without colouring the figures
        // themselves, which have to stay legible in a photocopy.
        borderLeft: `3px solid ${color}`,
      }}
    >
      <Typography sx={{ fontSize: 11, fontWeight: 600, color: GREY, letterSpacing: 0.4 }}>
        {title}
      </Typography>

      <Typography sx={{
        fontSize: 24, fontWeight: 700, color: INK, lineHeight: 1.15, mt: 0.3,
        fontFamily: MONO,
      }}>
        {primary}
      </Typography>

      {secondary && (
        <Typography sx={{ fontSize: 11.5, color: GREY }}>
          {secondary}
        </Typography>
      )}

      {series && chart.kind === 'spark' && <Spark series={series} colour={color} />}
      {series && chart.kind === 'bars' && <Bars series={series} colour={color} />}

      {caption && (
        <Typography sx={{ fontSize: 10, color: GREY_MUTED, mt: 0.8, lineHeight: 1.4 }}>
          {caption}
        </Typography>
      )}
    </Box>
  );
}

export default StatCard;
