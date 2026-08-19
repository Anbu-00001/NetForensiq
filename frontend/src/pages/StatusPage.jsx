import { useState } from 'react';
import { Box, Typography, TextField, Button, Alert, Grow } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import TravelExploreOutlinedIcon from '@mui/icons-material/TravelExploreOutlined';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import HourglassEmptyIcon from '@mui/icons-material/HourglassEmpty';
import CancelIcon from '@mui/icons-material/Cancel';
import { ConsoleBar, FieldLabel } from './LoginPage';
import { consoleField } from '../theme/formStyles';
import { checkApprovalStatus } from '../services/auth';

// Three stages, because the backend has three states.
//
// There used to be a fourth, "02 Identity verification", and stageIndex()
// returned 2 for any pending account — so it rendered COMPLETE with a green
// tick. Nothing in the codebase verifies anyone's identity: ApprovalStatusView
// reports submitted, approved or rejected, and an administrator's judgement is
// the only check that happens. Telling an applicant their identity had been
// verified was inventing a control.
const STAGES = [
  { key: 'submitted', num: '01', label: 'Credentials submitted' },
  { key: 'authorization', num: '02', label: 'Administrator review' },
  { key: 'granted', num: '03', label: 'Access granted' },
];

/**
 * How far through the three stages an application has got.
 *
 * `approved` is not "in progress at stage 3" — it is stage 3 finished, which
 * is why the page also offers a PROCEED TO TERMINAL button directly beneath.
 * Returning the index of the last stage made the final row read IN PROGRESS
 * next to a button saying the account was ready to use.
 *
 * Returning one past the end makes every stage `done` and none `current`,
 * which is what "finished" looks like.
 */
function stageIndex(stage) {
  if (stage === 'approved') return STAGES.length;   // all stages complete
  if (stage === 'rejected') return -1;
  return 1;   // submitted; awaiting an administrator
}

function StatusPage() {
  const [username, setUsername] = useState('');
  const [badgeId, setBadgeId] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleCheck = async (e) => {
    e.preventDefault();
    setError('');
    setResult(null);

    if (!username || !badgeId) {
      setError('Enter both your username and badge ID.');
      return;
    }

    setLoading(true);
    try {
      const data = await checkApprovalStatus(username, badgeId);
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Unable to retrieve enrollment status.');
    } finally {
      setLoading(false);
    }
  };

  const activeIdx = result ? stageIndex(result.stage) : -99;
  const rejected = result?.stage === 'rejected';

  return (
    <Box sx={{ minHeight: '100vh', backgroundColor: '#FFFFFF', display: 'flex', flexDirection: 'column' }}>
      <ConsoleBar />

      <Box
        sx={{
          flexGrow: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
          px: 2, py: 4, position: 'relative',
          backgroundImage: `
            linear-gradient(rgba(17,19,21,0.035) 1px, transparent 1px),
            linear-gradient(90deg, rgba(17,19,21,0.035) 1px, transparent 1px)
          `,
          backgroundSize: '46px 46px',
        }}
      >

        <Grow in appear timeout={620}>
          <Box
            sx={{
              width: '100%', maxWidth: 620, borderRadius: 2, overflow: 'hidden',
              backgroundColor: '#F4F5F7',
              border: '1px solid #E2E5E9',
              position: 'relative', zIndex: 1, p: { xs: 3, sm: 4 },
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.4, mb: 0.6 }}>
              <Box
                sx={{
                  width: 38, height: 38, borderRadius: 1.5,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  backgroundColor: 'rgba(138,97,0,0.09)',
                  border: '1px solid rgba(138,97,0,0.28)', color: '#8A6100',
                }}
              >
                <TravelExploreOutlinedIcon sx={{ fontSize: 21 }} />
              </Box>
              <Box>
                <Typography sx={{ fontSize: 17, fontWeight: 800, letterSpacing: 1.4 }}>
                  TRACK ENROLLMENT
                </Typography>
                <Typography
                  sx={{
                    fontSize: 10.5, letterSpacing: 0.8,
                    fontFamily: "'JetBrains Mono', monospace",
                    color: '#5A6068',
                  }}
                >
                  CHECK YOUR AUTHORIZATION STATUS
                </Typography>
              </Box>
            </Box>

            <Box sx={{ height: '1px', backgroundColor: '#E2E5E9', my: 2.4 }} />

            {error && (
              <Alert
                severity="error"
                sx={{
                  mb: 2, fontSize: 12.5,
                  backgroundColor: 'rgba(179,38,30,0.08)',
                  border: '1px solid rgba(179,38,30,0.25)', color: '#B3261E',
                }}
              >
                {error}
              </Alert>
            )}

            <form onSubmit={handleCheck}>
              <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' }, gap: 2 }}>
                <Box>
                  <FieldLabel text="USERNAME" />
                  <TextField
                    fullWidth size="small" sx={consoleField} placeholder="as registered"
                    value={username} onChange={(e) => setUsername(e.target.value)}
                  />
                </Box>
                <Box>
                  <FieldLabel text="BADGE / EMPLOYEE ID" />
                  <TextField
                    fullWidth size="small" sx={consoleField} placeholder="e.g. INV-0042"
                    value={badgeId} onChange={(e) => setBadgeId(e.target.value)}
                  />
                </Box>
              </Box>

              <Button
                type="submit" fullWidth variant="contained" disabled={loading}
                sx={{
                  mt: 2.8, py: 1.15, fontWeight: 700, fontSize: 13,
                  letterSpacing: 1.2, borderRadius: 1.5,
                  backgroundColor: '#8A6100', color: '#FFFFFF',
                  transition: 'all 0.25s cubic-bezier(0.4,0,0.2,1)',
                  '&:hover': {
                    backgroundColor: '#6F4E00',
                  },
                }}
              >
                {loading ? 'QUERYING…' : 'RETRIEVE STATUS'}
              </Button>
            </form>

            {result && (
              <Grow in timeout={500}>
                <Box sx={{ mt: 3.5 }}>
                  <Box sx={{ height: '1px', backgroundColor: '#E2E5E9', mb: 2.5 }} />

                  <Box
                    sx={{
                      display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1.5, mb: 3,
                      p: 1.8, borderRadius: 1.5,
                      backgroundColor: '#F4F5F7',
                      border: '1px solid #E2E5E9',
                    }}
                  >
                    <Meta k="OPERATOR" v={result.username} />
                    <Meta k="BADGE ID" v={result.badge_id} />
                    <Meta k="UNIT" v={result.department} />
                    <Meta k="REQUESTED ROLE" v={result.requested_role} />
                  </Box>

                  {rejected ? (
                    <Box
                      sx={{
                        display: 'flex', gap: 1.5, p: 2, borderRadius: 1.5,
                        backgroundColor: 'rgba(179,38,30,0.06)',
                        border: '1px solid rgba(179,38,30,0.22)',
                      }}
                    >
                      <CancelIcon sx={{ color: '#B3261E', fontSize: 22 }} />
                      <Box>
                        <Typography sx={{ fontSize: 13.5, fontWeight: 700, color: '#B3261E' }}>
                          Enrollment not authorized
                        </Typography>
                        <Typography sx={{ fontSize: 12, color: '#5A6068', mt: 0.4 }}>
                          Contact your unit administrator for clarification.
                        </Typography>
                      </Box>
                    </Box>
                  ) : (
                    STAGES.map((s, i) => {
                      const done = i < activeIdx;
                      const current = i === activeIdx;
                      const color = done ? '#1B6E3C' : current ? '#8A6100' : '#5F656D';

                      return (
                        <Box
                          key={s.key}
                          sx={{
                            display: 'flex', gap: 1.8, pb: 2.6, position: 'relative',
                            animation: `riseIn 0.45s ease ${i * 0.1}s both`,
                            '@keyframes riseIn': {
                              from: { opacity: 0, transform: 'translateY(8px)' },
                              to: { opacity: 1, transform: 'translateY(0)' },
                            },
                            '&::before': i < STAGES.length - 1 ? {
                              content: '""', position: 'absolute', left: 15, top: 32,
                              width: '1px', height: 'calc(100% - 32px)',
                              backgroundColor: done ? 'rgba(27,110,60,0.3)' : '#E2E5E9',
                            } : {},
                          }}
                        >
                          <Box
                            sx={{
                              width: 31, height: 31, flexShrink: 0, borderRadius: '50%',
                              display: 'flex', alignItems: 'center', justifyContent: 'center',
                              fontSize: 11, fontWeight: 700,
                              fontFamily: "'JetBrains Mono', monospace",
                              color: done || current ? '#FFFFFF' : '#5F656D',
                              backgroundColor: done ? '#1B6E3C' : current ? '#8A6100' : '#ECEEF1',
                              border: done || current ? 'none' : '1px solid #E2E5E9',
                              boxShadow: current ? '0 0 16px rgba(138,97,0,0.45)' : 'none',
                              zIndex: 1,
                              animation: current ? 'pulseNode 2.2s ease-in-out infinite' : 'none',
                            }}
                          >
                            {done ? <CheckCircleIcon sx={{ fontSize: 17 }} />
                              : current ? <HourglassEmptyIcon sx={{ fontSize: 16 }} />
                              : s.num}
                          </Box>

                          <Box sx={{ pt: 0.4 }}>
                            <Typography
                              sx={{
                                fontSize: 13.5, fontWeight: 500,
                                color: done || current ? '#111315' : '#5F656D',
                              }}
                            >
                              {s.label}
                            </Typography>
                            <Typography
                              sx={{
                                fontSize: 9.5, letterSpacing: 0.9, mt: 0.3,
                                fontFamily: "'JetBrains Mono', monospace", color,
                              }}
                            >
                              {done ? 'COMPLETE' : current ? 'IN PROGRESS' : 'PENDING'}
                            </Typography>
                          </Box>
                        </Box>
                      );
                    })
                  )}

                  {result.stage === 'approved' && (
                    <Button
                      component={RouterLink} to="/login" fullWidth variant="contained"
                      sx={{
                        mt: 1, py: 1.15, fontWeight: 700, fontSize: 13,
                        letterSpacing: 1.2, borderRadius: 1.5,
                        backgroundColor: '#1B6E3C', color: '#FFFFFF',
                        '&:hover': { backgroundColor: '#155B31' },
                      }}
                    >
                      PROCEED TO TERMINAL
                    </Button>
                  )}
                </Box>
              </Grow>
            )}

            <Typography sx={{ fontSize: 12.5, color: '#5A6068', mt: 3, textAlign: 'center' }}>
              <RouterLink to="/login" style={{ color: '#076E7C', textDecoration: 'none', fontWeight: 600 }}>
                Return to terminal
              </RouterLink>
            </Typography>
          </Box>
        </Grow>
      </Box>
    </Box>
  );
}

function Meta({ k, v }) {
  return (
    <Box>
      <Typography
        sx={{
          fontSize: 9, letterSpacing: 1,
          fontFamily: "'JetBrains Mono', monospace", color: '#5A6068',
        }}
      >
        {k}
      </Typography>
      <Typography
        sx={{
          fontSize: 12.5, fontFamily: "'JetBrains Mono', monospace",
          color: '#111315', textTransform: 'capitalize',
        }}
      >
        {v || '—'}
      </Typography>
    </Box>
  );
}

export default StatusPage;