import { Box, Typography } from '@mui/material';
import { SEVERITY_COLOR } from '../../services/forensics';
import { GUJARATI } from '../../i18n/gujarati';

const ORDER = ['critical', 'high', 'medium', 'low'];

/** Detection counts by severity for the selected capture. */
function SeverityBreakdown({ data = [] }) {
  const counts = Object.fromEntries(data.map((d) => [d.severity, d.count]));
  const total = data.reduce((sum, d) => sum + d.count, 0);

  return (
    <Box
      sx={{
        p: 2.5,
        borderRadius: 2,
        backgroundColor: '#F4F5F7',
        border: '1px solid #E2E5E9',
      }}
    >
      <Typography sx={{ fontSize: 13.5, fontWeight: 600, mb: 0.5 }}>
        Findings by severity{' '}
        <Box component="span" lang="gu" sx={{
          fontWeight: 400, color: '#2B3138',
        }}>
          ({GUJARATI.severity})
        </Box>
      </Typography>
      <Typography sx={{ fontSize: 11.5, color: '#5A6068', mb: 2 }}>
        Every finding records the rule, the observed value and the threshold it was compared against
      </Typography>

      {total === 0 ? (
        <Typography sx={{ fontSize: 12.5, color: '#5A6068' }}>
          No detections yet — run detection on this capture.
        </Typography>
      ) : (
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          {ORDER.filter((s) => counts[s]).map((sev) => (
            <Box
              key={sev}
              sx={{
                flex: '1 1 120px',
                p: 1.5,
                borderRadius: 1.5,
                border: `1px solid ${SEVERITY_COLOR[sev]}44`,
                backgroundColor: `${SEVERITY_COLOR[sev]}0F`,
              }}
            >
              <Typography sx={{ fontSize: 26, fontWeight: 700, color: SEVERITY_COLOR[sev] }}>
                {counts[sev]}
              </Typography>
              <Typography sx={{
                fontSize: 11.5, textTransform: 'uppercase', letterSpacing: 0.6,
                color: '#5A6068',
              }}>
                {sev}
              </Typography>
            </Box>
          ))}
        </Box>
      )}
    </Box>
  );
}

export default SeverityBreakdown;
