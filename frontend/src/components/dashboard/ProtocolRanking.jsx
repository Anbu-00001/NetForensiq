import { Box, Typography } from '@mui/material';

/**
 * Application-protocol breakdown for the selected capture.
 * Counts come from the API; nothing is authored here.
 */
function ProtocolRanking({ applications = [] }) {
  const max = Math.max(...applications.map((a) => a.count), 1);

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
        Application protocols
      </Typography>

      {!applications.length ? (
        <Typography sx={{ fontSize: 12, color: 'rgba(229,231,235,0.4)' }}>
          No application protocols identified in this capture.
        </Typography>
      ) : (
        applications.map((row) => (
          <Box key={row.app_protocol} sx={{ mb: 1.2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.4 }}>
              <Typography sx={{ fontSize: 12.5, color: '#E5E7EB' }}>
                {row.app_protocol}
              </Typography>
              <Typography sx={{ fontSize: 12.5, color: 'rgba(229,231,235,0.55)' }}>
                {row.count.toLocaleString()}
              </Typography>
            </Box>
            <Box sx={{ height: 4, borderRadius: 2, backgroundColor: 'rgba(255,255,255,0.06)' }}>
              <Box
                sx={{
                  height: '100%',
                  width: `${(row.count / max) * 100}%`,
                  borderRadius: 2,
                  backgroundColor: '#00D4FF',
                  boxShadow: '0 0 8px rgba(0,212,255,0.4)',
                }}
              />
            </Box>
          </Box>
        ))
      )}
    </Box>
  );
}

export default ProtocolRanking;
