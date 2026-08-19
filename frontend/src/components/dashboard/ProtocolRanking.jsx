import { Box, Typography } from '@mui/material';

/**
 * Application-protocol breakdown for the selected capture.
 * Counts come from the API; nothing is authored here.
 *
 * Each row says how much of it was actually read off the wire. A protocol
 * assigned from the port number alone is a guess — "SSH because it was on 22"
 * — and a covert channel on a permitted port is precisely the case where the
 * guess is wrong. Presenting both kinds under one label would hide that.
 */
function ProtocolRanking({ applications = [] }) {
  const max = Math.max(...applications.map((a) => a.count), 1);

  return (
    <Box
      sx={{
        p: 2,
        borderRadius: 2,
        backgroundColor: '#F4F5F7',
        border: '1px solid #E2E5E9',
      }}
    >
      <Typography sx={{ fontSize: 13.5, fontWeight: 600, mb: 1.5 }}>
        Application protocols
      </Typography>

      {!applications.length ? (
        <Typography sx={{ fontSize: 12, color: '#5A6068' }}>
          No application protocols identified in this capture.
        </Typography>
      ) : (
        applications.map((row) => (
          <Box key={row.app_protocol} sx={{ mb: 1.2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.4 }}>
              <Typography sx={{ fontSize: 12.5, color: '#111315' }}>
                {row.app_protocol}
              </Typography>
              <Typography sx={{ fontSize: 12.5, color: '#5A6068' }}>
                {row.count.toLocaleString()}
                {row.inferred_from_port > 0 && (
                  <Box component="span" sx={{ fontSize: 11, color: '#8A6100', ml: 0.8 }}>
                    {row.observed > 0
                      ? `${row.inferred_from_port.toLocaleString()} from port only`
                      : 'from port only'}
                  </Box>
                )}
              </Typography>
            </Box>
            <Box sx={{ height: 4, borderRadius: 2, backgroundColor: '#E2E5E9' }}>
              <Box
                sx={{
                  height: '100%',
                  width: `${(row.count / max) * 100}%`,
                  borderRadius: 2,
                  backgroundColor: '#1F3A5F',
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
