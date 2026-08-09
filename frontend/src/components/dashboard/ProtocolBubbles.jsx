import { Box, Typography } from '@mui/material';

const bubbles = [
  { label: 'TCP', value: 80, pct: '54%', r: 52, x: 150, y: 150, color: '#00A8FF', glow: '#00D4FF' },
  { label: 'UDP', value: 52, pct: '34%', r: 34, x: 72, y: 232, color: '#FF6A2B', glow: '#FF8A3D' },
  { label: 'TLS', value: 162, pct: '27%', r: 33, x: 228, y: 230, color: '#A855F7', glow: '#C084FC' },
  { label: 'DNS', value: 32, pct: '19%', r: 25, x: 62, y: 68, color: '#00C46A', glow: '#00E68A' },
  { label: 'ICMP', value: 54, pct: '11%', r: 26, x: 246, y: 72, color: '#E0234E', glow: '#FF3B5C' },
  { label: '', value: '', pct: '', r: 13, x: 158, y: 42, color: '#2B7FFF', glow: '#3B82F6' },
  { label: '', value: '', pct: '', r: 10, x: 258, y: 158, color: '#2B7FFF', glow: '#3B82F6' },
  { label: '', value: '', pct: '', r: 8, x: 52, y: 158, color: '#00D4FF', glow: '#00D4FF' },
];

function ProtocolBubbles() {
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
        Protocol Traffic Domain
      </Typography>

      <Box sx={{ display: 'flex', justifyContent: 'center' }}>
        <svg viewBox="0 0 300 300" style={{ width: '100%', maxWidth: 300 }}>
          <defs>
            {bubbles.map((b, i) => (
              <radialGradient key={i} id={`bub${i}`} cx="35%" cy="30%">
                <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.75" />
                <stop offset="45%" stopColor={b.glow} stopOpacity="0.9" />
                <stop offset="100%" stopColor={b.color} stopOpacity="1" />
              </radialGradient>
            ))}
            <filter id="softGlow" x="-70%" y="-70%" width="240%" height="240%">
              <feGaussianBlur stdDeviation="7" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* orbital rings */}
          <circle
            cx="150" cy="150" r="118"
            fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="1"
            strokeDasharray="3 7"
          >
            <animateTransform
              attributeName="transform" type="rotate"
              from="0 150 150" to="360 150 150"
              dur="60s" repeatCount="indefinite"
            />
          </circle>
          <circle
            cx="150" cy="150" r="96"
            fill="none" stroke="rgba(0,212,255,0.1)" strokeWidth="1"
            strokeDasharray="40 200"
          >
            <animateTransform
              attributeName="transform" type="rotate"
              from="360 150 150" to="0 150 150"
              dur="24s" repeatCount="indefinite"
            />
          </circle>

          {bubbles.map((b, i) => (
            <g key={i} filter="url(#softGlow)">
              <circle cx={b.x} cy={b.y} r={b.r} fill={`url(#bub${i})`} opacity="0.95">
                <animate
                  attributeName="r"
                  values={`${b.r};${b.r * 1.05};${b.r}`}
                  dur={`${3 + i * 0.4}s`}
                  repeatCount="indefinite"
                />
              </circle>
              {b.label && (
                <>
                  <text
                    x={b.x} y={b.y - 6} textAnchor="middle"
                    fill="rgba(255,255,255,0.85)" fontSize={b.r > 40 ? 11 : 8.5}
                    fontFamily="'JetBrains Mono', monospace"
                  >
                    {b.label}
                  </text>
                  <text
                    x={b.x} y={b.y + (b.r > 40 ? 10 : 6)} textAnchor="middle"
                    fill="#FFFFFF" fontSize={b.r > 40 ? 20 : 14} fontWeight="700"
                    fontFamily="'Inter', sans-serif"
                  >
                    {b.value}
                  </text>
                  <text
                    x={b.x} y={b.y + (b.r > 40 ? 24 : 17)} textAnchor="middle"
                    fill="rgba(255,255,255,0.6)" fontSize="8"
                    fontFamily="'JetBrains Mono', monospace"
                  >
                    {b.pct}
                  </text>
                </>
              )}
            </g>
          ))}
        </svg>
      </Box>
    </Box>
  );
}

export default ProtocolBubbles;