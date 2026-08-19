import { useNavigate } from 'react-router-dom';
import { login } from '../services/auth';
import { useEffect, useState } from 'react';
import { consoleField } from '../theme/formStyles';
import ClassificationBanner from '../components/layout/ClassificationBanner';
import { getEngineInfo } from '../services/engine';
import {
  Box, Typography, TextField, Button, InputAdornment, IconButton, Alert, Grow,
} from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import ShieldOutlinedIcon from '@mui/icons-material/ShieldOutlined';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';

function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
  e.preventDefault();
  setError('');

  if (!username || !password) {
    setError('Both credentials are required.');
    return;
  }

  setLoading(true);
  try {
    await login(username, password);
    navigate('/dashboard');
  } catch (err) {
    // Say what actually went wrong.
    //
    // Every failure used to fall back to "Authentication failed. Verify your
    // credentials." — including the API being unreachable, which is not a
    // credentials problem and sends the officer to re-check something that was
    // never wrong. A tool that reports the wrong cause costs more time than one
    // that reports nothing.
    const status = err.response?.status;
    const detail = err.response?.data?.detail
      || err.response?.data?.non_field_errors?.[0];

    let message;
    if (!err.response) {
      // No response at all: the request never reached a server.
      message = 'Could not reach the server. Check that the platform is running,'
        + ' then try again.';
    } else if (status === 429) {
      // DRF's own message names the wait, so prefer it when present.
      message = detail
        || 'Too many sign-in attempts from this address. Wait, then try again.';
    } else if (status >= 500) {
      message = 'The server failed while handling the sign-in. This is not a'
        + ' problem with your credentials.';
    } else {
      message = detail || 'Authentication failed. Verify your credentials.';
    }
    setError(message);
  } finally {
    setLoading(false);
  }
};

  return (
    <Box
      sx={{
        minHeight: '100vh',
        backgroundColor: '#FFFFFF',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <ConsoleBar />

      <Box
        sx={{
          flexGrow: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          px: 2,
          py: 4,
          position: 'relative',
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
              display: 'flex',
              flexDirection: { xs: 'column', md: 'row' },
              width: '100%',
              maxWidth: 880,
              borderRadius: 2,
              overflow: 'hidden',
              backgroundColor: '#F4F5F7',
              border: '1px solid #E2E5E9',
              position: 'relative',
              zIndex: 1,
            }}
          >
            <TelemetryPanel />

            {/* ── FORM SIDE ── */}
            <Box sx={{ flex: 1, p: { xs: 3, sm: 4.5 }, minWidth: 0 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.4, mb: 0.6 }}>
                <Box
                  sx={{
                    width: 38, height: 38, borderRadius: 1.5,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    backgroundColor: 'rgba(7,110,124,0.10)',
                    border: '1px solid rgba(7,110,124,0.34)',
                    color: '#076E7C',
                  }}
                >
                  <ShieldOutlinedIcon sx={{ fontSize: 21 }} />
                </Box>
                <Box>
                  <Typography sx={{ fontSize: 17, fontWeight: 800, letterSpacing: 1.6 }}>
                    NETFORENSIQ
                  </Typography>
                  <Typography
                    sx={{
                      fontSize: 10.5, letterSpacing: 0.8,
                      fontFamily: "'JetBrains Mono', monospace",
                      color: '#5A6068',
                    }}
                  >
                    SECURE ACCESS TERMINAL
                  </Typography>
                </Box>
              </Box>

              <Box sx={{ height: '1px', backgroundColor: '#E2E5E9', my: 2.5 }} />

              <Typography sx={{ fontSize: 13, color: '#5A6068', mb: 2.5 }}>
                Authenticate with your issued departmental credentials.
              </Typography>

              {error && (
                <Alert
                  severity="error"
                  sx={{
                    mb: 2, fontSize: 12.5,
                    backgroundColor: 'rgba(179,38,30,0.08)',
                    border: '1px solid rgba(179,38,30,0.25)',
                    color: '#B3261E',
                  }}
                >
                  {error}
                </Alert>
              )}

              <form onSubmit={handleSubmit}>
                <FieldLabel text="OPERATOR ID" />
                <TextField
                  fullWidth size="small" value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="username"
                  autoComplete="username"
                  sx={consoleField}
                />

                <Box sx={{ mt: 2 }}>
                  <FieldLabel text="PASSPHRASE" />
                  <TextField
                    fullWidth size="small"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    autoComplete="current-password"
                    sx={consoleField}
                    slotProps={{ input: {
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton
                            onClick={() => setShowPassword(!showPassword)}
                            edge="end" size="small"
                            sx={{ color: '#5A6068' }}
                          >
                            {showPassword ? <VisibilityOff sx={{ fontSize: 17 }} />
                              : <Visibility sx={{ fontSize: 17 }} />}
                          </IconButton>
                        </InputAdornment>
                      ),
                    } }}
                  />
                </Box>

                <Button
                  type="submit" fullWidth variant="contained"
                  disabled={loading}
                  startIcon={<LockOutlinedIcon sx={{ fontSize: 17 }} />}
                  sx={{
                    mt: 3.2, py: 1.15, fontWeight: 700, fontSize: 13,
                    letterSpacing: 1.2, borderRadius: 1.5,
                    backgroundColor: '#111315', color: '#FFFFFF',
                    transition: 'all 0.25s cubic-bezier(0.4,0,0.2,1)',
                    '&:hover': {
                      backgroundColor: '#2B3138',
                    },
                  }}
                >
                  {loading ? 'AUTHENTICATING…' : 'AUTHENTICATE'}
                </Button>
              </form>

              <Typography sx={{ fontSize: 12.5, color: '#5A6068', mt: 2.5, textAlign: 'center' }}>
                No credentials issued?{' '}
                <RouterLink
                  to="/register"
                  style={{ color: '#076E7C', textDecoration: 'none', fontWeight: 600 }}
                >
                  Request enrollment
                </RouterLink>
              </Typography>

              <Typography sx={{ fontSize: 12.5, color: '#5A6068', mt: 0.8, textAlign: 'center' }}>
                Awaiting authorization?{' '}
                <RouterLink
                  to="/status"
                  style={{ color: '#8A6100', textDecoration: 'none', fontWeight: 600 }}
                >
                  Track your request
                </RouterLink>
              </Typography>

              <Box
                sx={{
                  mt: 2.5, p: 1.4, borderRadius: 1.5,
                  backgroundColor: 'rgba(179,38,30,0.045)',
                  border: '1px solid rgba(179,38,30,0.16)',
                }}
              >
                <Typography
                  sx={{
                    fontSize: 10.5, lineHeight: 1.7, textAlign: 'center',
                    fontFamily: "'JetBrains Mono', monospace",
                    color: '#5A6068',
                  }}
                >
                  SIGN-IN ATTEMPTS ARE RECORDED WITH TIMESTAMP,
                  <br />USERNAME AND SOURCE ADDRESS
                </Typography>
              </Box>
            </Box>
          </Box>
        </Grow>
      </Box>
    </Box>
  );
}

/* ───────── shared pieces ───────── */


export function FieldLabel({ text }) {
  return (
    <Typography
      sx={{
        fontSize: 10, letterSpacing: 1.4, mb: 0.7,
        fontFamily: "'JetBrains Mono', monospace",
        color: '#5A6068',
      }}
    >
      {text}
    </Typography>
  );
}

export function ConsoleBar() {
  // Sign-in, registration, the landing page and the status page genuinely hold
  // no case material, so they say so rather than borrowing a marking they have
  // not earned.
  return <ClassificationBanner level="unclassified" />;
}

export function Dot({ color, label }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.7 }}>
      <Box
        sx={{
          width: 6, height: 6, borderRadius: '50%',
          backgroundColor: color, boxShadow: `0 0 7px ${color}`,
        }}
      />
      <Typography
        sx={{
          fontSize: 10, letterSpacing: 0.7,
          fontFamily: "'JetBrains Mono', monospace",
          color: '#5A6068',
        }}
      >
        {label}
      </Typography>
    </Box>
  );
}

export function TelemetryPanel() {
  // The rule count is read from the engine rather than written into the copy.
  const [engine, setEngine] = useState(null);

  useEffect(() => {
    let live = true;
    getEngineInfo()
      .then((info) => { if (live) setEngine(info); })
      .catch(() => {});
    return () => { live = false; };
  }, []);

  return (
    <Box
      sx={{
        width: { xs: '100%', md: 300 },
        flexShrink: 0,
        p: 3,
        backgroundColor: '#F4F5F7',
        borderRight: { md: '1px solid #E2E5E9' },
        borderBottom: { xs: '1px solid #E2E5E9', md: 'none' },
        position: 'relative',
      }}
    >
      <Typography
        sx={{
          fontSize: 10, letterSpacing: 1.6, mb: 1.4,
          fontFamily: "'JetBrains Mono', monospace",
          color: '#5A6068',
        }}
      >
        CAPABILITIES
      </Typography>

      {/*
        These were rendered as live status — "Capture engine ACTIVE",
        "Detection model ACTIVE" — from hardcoded strings, on a page shown
        before anyone has authenticated, so no API could have backed them.
        "Detection model" was doubly untrue: there is no model, only rules.
        They now describe what the system does, not what it is doing.
      */}
      {[
        ['Packet analysis', 'PCAP', '#1B6E3C'],
        ['Detection', `${engine?.rule_count ?? '—'} RULES, SOURCED OR TAGGED`, '#1B6E3C'],
        ['Evidence', 'SHA-256 SEALED', '#076E7C'],
        ['Certificate', 'BSA s.63', '#8A6100'],
      ].map(([k, v, c], i) => (
        <Box
          key={k}
          sx={{
            display: 'flex', alignItems: 'center', py: 0.75,
            borderBottom: i < 3 ? '1px solid #F4F5F7' : 'none',
            animation: `riseIn 0.45s ease ${0.32 + i * 0.06}s both`,
          }}
        >
          <Typography sx={{ fontSize: 11.5, color: '#5A6068', flexGrow: 1 }}>
            {k}
          </Typography>
          <Box sx={{ width: 5, height: 5, borderRadius: '50%', backgroundColor: c, boxShadow: `0 0 6px ${c}`, mr: 0.8 }} />
          <Typography
            sx={{ fontSize: 10, letterSpacing: 0.6, color: c, fontFamily: "'JetBrains Mono', monospace" }}
          >
            {v}
          </Typography>
        </Box>
      ))}
    </Box>
  );
}

export default LoginPage;