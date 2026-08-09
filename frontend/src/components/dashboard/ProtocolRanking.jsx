import { Box, Typography } from '@mui/material';
import ArrowDropUpIcon from '@mui/icons-material/ArrowDropUp';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';

const rows = [
  { protocol: 'HTTPS', packets: 8631, trend: 10, up: true },
  { protocol: 'DNS', packets: 4176, trend: 8, up: false },
  { protocol: 'TCP', packets: 3437, trend: 12, up: false },
  { protocol: 'ICMP', packets: 1654, trend: 11, up: true },
  { protocol: 'SMTP', packets: 322, trend: 4, up: false },
];

function ProtocolRanking() {
  return (
    <Box
      sx={{
        p: 2,
        borderRadius: 2,
        backgroundColor: 'rgba(255,255,255,0.02)',
        border: '1px solid rgba(255,255,255,0.06)',
      }}
    >
      <Typography sx={{ fontSize: 13.5, fontWeight: 600, mb: 1.5 }}>
        Session Protocol Ranking
      </Typography>

      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr 1fr',
          pb: 1,
          borderBottom: '1px solid rgba(255,255,255,0.06)',
        }}
      >
        {['Protocol', 'Packets', 'Tendency'].map((h, i) => (
          <Typography
            key={h}
            sx={{
              fontSize: 11,
              color: 'rgba(229,231,235,0.4)',
              letterSpacing: 0.5,
              textAlign: i === 2 ? 'right' : 'left',
            }}
          >
            {h}
          </Typography>
        ))}
      </Box>

      {rows.map((r, i) => (
        <Box
          key={r.protocol}
          sx={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr 1fr',
            alignItems: 'center',
            py: 1.15,
            borderBottom: i < rows.length - 1 ? '1px solid rgba(255,255,255,0.035)' : 'none',
            cursor: 'pointer',
            transition: 'background 0.2s',
            animation: `fadeRow 0.4s ease ${0.1 + i * 0.06}s both`,
            '@keyframes fadeRow': {
              from: { opacity: 0, transform: 'translateX(8px)' },
              to: { opacity: 1, transform: 'translateX(0)' },
            },
            '&:hover': { backgroundColor: 'rgba(0,212,255,0.04)' },
          }}
        >
          <Typography
            sx={{ fontSize: 12.5, fontFamily: "'JetBrains Mono', monospace", color: '#E5E7EB' }}
          >
            {r.protocol}
          </Typography>
          <Typography
            sx={{
              fontSize: 12.5,
              fontFamily: "'JetBrains Mono', monospace",
              color: 'rgba(229,231,235,0.7)',
            }}
          >
            {r.packets.toLocaleString()}
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end' }}>
            {r.up ? (
              <ArrowDropUpIcon sx={{ fontSize: 20, color: '#FF3B5C' }} />
            ) : (
              <ArrowDropDownIcon sx={{ fontSize: 20, color: '#00E68A' }} />
            )}
            <Typography
              sx={{
                fontSize: 12,
                fontFamily: "'JetBrains Mono', monospace",
                color: r.up ? '#FF3B5C' : '#00E68A',
              }}
            >
              {r.trend}%
            </Typography>
          </Box>
        </Box>
      ))}
    </Box>
  );
}

export default ProtocolRanking;