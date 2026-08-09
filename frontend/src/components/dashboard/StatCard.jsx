import { Box, Typography } from '@mui/material';

function StatCard({ title, primary, secondary, color, data, delay = 0 }) {
  const max = Math.max(...data);

  return (
    <Box
      sx={{
        flex: 1,
        minWidth: 168,
        p: 1.8,
        borderRadius: 2,
        backgroundColor: 'rgba(255,255,255,0.025)',
        border: '1px solid rgba(255,255,255,0.06)',
        transition: 'all 0.3s cubic-bezier(0.4,0,0.2,1)',
        animation: `cardRise 0.5s ease ${delay}s both`,
        '@keyframes cardRise': {
          from: { opacity: 0, transform: 'translateY(14px)' },
          to: { opacity: 1, transform: 'translateY(0)' },
        },
        '&:hover': {
          borderColor: `${color}55`,
          backgroundColor: 'rgba(255,255,255,0.04)',
          transform: 'translateY(-3px)',
          boxShadow: `0 8px 24px -8px ${color}40`,
        },
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1.2 }}>
        <Typography sx={{ fontSize: 13, fontWeight: 600, color: 'rgba(229,231,235,0.85)' }}>
          {title}
        </Typography>
        <Box
          sx={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            backgroundColor: color,
            boxShadow: `0 0 8px ${color}`,
            animation: 'blip 2s ease-in-out infinite',
            '@keyframes blip': { '0%,100%': { opacity: 1 }, '50%': { opacity: 0.35 } },
          }}
        />
      </Box>

      <Box sx={{ display: 'flex', alignItems: 'flex-end', gap: '2px', height: 34, mb: 1.4 }}>
        {data.map((v, i) => (
          <Box
            key={i}
            sx={{
              flex: 1,
              height: `${(v / max) * 100}%`,
              borderRadius: '1px',
              background: `linear-gradient(180deg, ${color} 0%, ${color}30 100%)`,
              transformOrigin: 'bottom',
              animation: `growBar 0.5s ease ${delay + i * 0.02}s both`,
              '@keyframes growBar': {
                from: { transform: 'scaleY(0)' },
                to: { transform: 'scaleY(1)' },
              },
            }}
          />
        ))}
      </Box>

      <Row color="rgba(229,231,235,0.3)" value={primary} />
      <Row color={color} value={secondary} />
    </Box>
  );
}

function Row({ color, value }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mb: 0.4 }}>
      <Box sx={{ width: 5, height: 5, borderRadius: '50%', backgroundColor: color }} />
      <Typography
        sx={{
          fontSize: 12,
          fontFamily: "'JetBrains Mono', monospace",
          color: 'rgba(229,231,235,0.75)',
        }}
      >
        {value}
      </Typography>
    </Box>
  );
}

export default StatCard;