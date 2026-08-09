import { Box, Typography } from '@mui/material';

function HexHeatmap({ title, baseColor, seed = 1 }) {
  const cols = 34;
  const rows = 6;
  const hexW = 13;
  const hexH = 11;

  const cells = [];
  let n = seed;
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      n = (n * 9301 + 49297) % 233280;
      const rnd = n / 233280;
      cells.push({
        x: c * hexW + (r % 2 ? hexW / 2 : 0) + 8,
        y: r * hexH + 10,
        v: rnd,
        i: r * cols + c,
      });
    }
  }

  const hexPath = (cx, cy, s) => {
    const pts = [];
    for (let i = 0; i < 6; i++) {
      const a = (Math.PI / 180) * (60 * i - 30);
      pts.push(`${cx + s * Math.cos(a)},${cy + s * Math.sin(a)}`);
    }
    return pts.join(' ');
  };

  return (
    <Box
      sx={{
        flex: 1,
        p: 2,
        borderRadius: 2,
        backgroundColor: 'rgba(255,255,255,0.02)',
        border: '1px solid rgba(255,255,255,0.06)',
      }}
    >
      <Typography sx={{ fontSize: 12, color: 'rgba(229,231,235,0.55)', mb: 1 }}>{title}</Typography>
      <svg viewBox={`0 0 ${cols * hexW + 20} ${rows * hexH + 20}`} style={{ width: '100%' }}>
        {cells.map((cell) => (
          <polygon
            key={cell.i}
            points={hexPath(cell.x, cell.y, 5.6)}
            fill={cell.v > 0.25 ? baseColor : '#1B2333'}
            opacity={cell.v > 0.25 ? 0.28 + cell.v * 0.72 : 0.55}
            style={{
              animation: `hexIn 0.4s ease ${(cell.i % 40) * 0.012}s both`,
            }}
          />
        ))}
        <style>{`@keyframes hexIn { from { opacity:0; transform:scale(0.4);} }`}</style>
      </svg>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.5 }}>
        {['0', '400', '800', '1.2k', '1.6k', '2k'].map((t) => (
          <Typography
            key={t}
            sx={{ fontSize: 9.5, color: 'rgba(229,231,235,0.3)', fontFamily: "'JetBrains Mono', monospace" }}
          >
            {t}
          </Typography>
        ))}
      </Box>
    </Box>
  );
}

export default HexHeatmap;