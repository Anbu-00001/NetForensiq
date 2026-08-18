import { Box, Typography } from '@mui/material';

const PALETTE = {
  TCP: { color: '#00A8FF', glow: '#00D4FF' },
  UDP: { color: '#FF6A2B', glow: '#FF8A3D' },
  ICMP: { color: '#E0234E', glow: '#FF3B5C' },
  OTHER: { color: '#A855F7', glow: '#C084FC' },
};

/**
 * Transport-protocol mix, sized by flow count.
 *
 * Radii are derived from the square root of each count so that *area*, not
 * radius, is proportional to the value — sizing by radius exaggerates large
 * categories roughly quadratically.
 */
function ProtocolBubbles({ protocols = [] }) {
  const total = protocols.reduce((sum, p) => sum + p.count, 0);
  const maxCount = Math.max(...protocols.map((p) => p.count), 1);

  const positions = [
    { x: 150, y: 140 }, { x: 78, y: 226 }, { x: 226, y: 226 },
    { x: 70, y: 66 }, { x: 236, y: 70 },
  ];

  const bubbles = protocols.slice(0, 5).map((p, i) => ({
    label: p.protocol,
    count: p.count,
    pct: total ? Math.round((p.count / total) * 100) : 0,
    r: 16 + Math.sqrt(p.count / maxCount) * 40,
    ...positions[i],
    ...(PALETTE[p.protocol] ?? PALETTE.OTHER),
  }));

  return (
    <Box
      sx={{
        p: 2,
        borderRadius: 2,
        backgroundColor: 'rgba(255,255,255,0.02)',
        border: '1px solid rgba(255,255,255,0.06)',
      }}
    >
      <Typography sx={{ fontSize: 13.5, fontWeight: 600, mb: 1 }}>
        Transport protocol mix
      </Typography>

      {!bubbles.length ? (
        <Typography sx={{ fontSize: 12, color: 'rgba(229,231,235,0.55)' }}>
          No flows in this capture.
        </Typography>
      ) : (
        <Box sx={{ display: 'flex', justifyContent: 'center' }}>
          <svg viewBox="0 0 300 300" style={{ width: '100%', maxWidth: 300 }}>
            {bubbles.map((b) => (
              <g key={b.label}>
                <circle cx={b.x} cy={b.y} r={b.r} fill={b.color} opacity={0.22} />
                <circle cx={b.x} cy={b.y} r={b.r} fill="none" stroke={b.glow}
                  strokeWidth={1.5} opacity={0.85} />
                <text x={b.x} y={b.y - 2} textAnchor="middle" fill="#E5E7EB"
                  fontSize={b.r > 30 ? 14 : 11} fontWeight={600}>
                  {b.label}
                </text>
                <text x={b.x} y={b.y + 14} textAnchor="middle"
                  fill="rgba(229,231,235,0.6)" fontSize={10.5}>
                  {b.pct}%
                </text>
              </g>
            ))}
          </svg>
        </Box>
      )}
    </Box>
  );
}

export default ProtocolBubbles;
