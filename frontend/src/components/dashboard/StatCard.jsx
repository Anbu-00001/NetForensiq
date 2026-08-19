import { Box, Typography } from '@mui/material';

function StatCard({ title, primary, secondary, color, data, delay = 0 }) {
  // The sparkline is decorative and optional. It is only rendered when real
  // series data is supplied — an invented trend line beside a real figure
  // would imply history the capture does not contain.
  const series = Array.isArray(data) && data.length ? data : null;
  const max = series ? Math.max(...series) : 0;

  return (
    <Box
      sx={{
        flex: 1,
        minWidth: 168,
        p: 1.8,
        borderRadius: 2,
        backgroundColor: '#F4F5F7',
        border: '1px solid #E2E5E9',
        transition: 'all 0.3s cubic-bezier(0.4,0,0.2,1)',
        animation: `cardRise 0.5s ease ${delay}s both`,
        '@keyframes cardRise': {
          from: { opacity: 0, transform: 'translateY(14px)' },
          to: { opacity: 1, transform: 'translateY(0)' },
        },
        '&:hover': {
          borderColor: `${color}55`,
          backgroundColor: '#F4F5F7',
        },
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1.2 }}>
        <Typography sx={{ fontSize: 13, fontWeight: 600, color: '#2B3138' }}>
          {title}
        </Typography>
        <Box
          sx={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            backgroundColor: color,
          }}
        />
      </Box>

      {series && (
      <Box sx={{ display: 'flex', alignItems: 'flex-end', gap: '2px', height: 34, mb: 1.4 }}>
        {series.map((v, i) => (
          <Box
            key={i}
            sx={{
              flex: 1,
              height: `${(v / max) * 100}%`,
              borderRadius: '1px',
              backgroundColor: color,
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
      )}

      <Row color="#6B7178" value={primary} />
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
          color: '#2B3138',
        }}
      >
        {value}
      </Typography>
    </Box>
  );
}

export default StatCard;