import { useNavigate } from 'react-router-dom';
import { login } from '../services/auth';
import { useState, useEffect } from 'react';
import {
  Box, Typography, TextField, Button, InputAdornment, IconButton, Alert, Grow,
} from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import ShieldOutlinedIcon from '@mui/icons-material/ShieldOutlined';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';

const spark = (s) =>
  Array.from({ length: 20 }, (_, i) => 18 + Math.abs(Math.sin(i * s) * 48) + (i % 3) * 6);

function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [mounted, setMounted] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => { setMounted(true); }, []);

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
    const detail = err.response?.data?.detail
      || err.response?.data?.non_field_errors?.[0]
      || 'Authentication failed. Verify your credentials.';
    setError(detail);
  } finally {
    setLoading(false);
  }
};

  return (
    <Box
      sx={{
        minHeight: '100vh',
        backgroundColor: '#080B14',
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
            linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px)
          `,
          backgroundSize: '46px 46px',
        }}
      >
        <Box
          sx={{
            position: 'absolute',
            width: 760, height: 760, borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(0,212,255,0.07) 0%, transparent 68%)',
            top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            pointerEvents: 'none',
          }}
        />

        <Grow in={mounted} timeout={620}>
          <Box
            sx={{
              display: 'flex',
              flexDirection: { xs: 'column', md: 'row' },
              width: '100%',
              maxWidth: 880,
              borderRadius: 2,
              overflow: 'hidden',
              backgroundColor: 'rgba(255,255,255,0.02)',
              border: '1px solid rgba(255,255,255,0.07)',
              boxShadow: '0 24px 70px -20px rgba(0,0,0,0.75)',
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
                    backgroundColor: 'rgba(0,212,255,0.09)',
                    border: '1px solid rgba(0,212,255,0.28)',
                    color: '#00D4FF',
                    animation: 'glowPulse 3s ease-in-out infinite',
                    '@keyframes glowPulse': {
                      '0%,100%': { boxShadow: '0 0 0 0 rgba(0,212,255,0.3)' },
                      '50%': { boxShadow: '0 0 0 8px rgba(0,212,255,0)' },
                    },
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
                      color: 'rgba(229,231,235,0.42)',
                    }}
                  >
                    SECURE ACCESS TERMINAL
                  </Typography>
                </Box>
              </Box>

              <Box sx={{ height: '1px', backgroundColor: 'rgba(255,255,255,0.07)', my: 2.5 }} />

              <Typography sx={{ fontSize: 13, color: 'rgba(229,231,235,0.55)', mb: 2.5 }}>
                Authenticate with your issued departmental credentials.
              </Typography>

              {error && (
                <Alert
                  severity="error"
                  sx={{
                    mb: 2, fontSize: 12.5,
                    backgroundColor: 'rgba(255,59,92,0.08)',
                    border: '1px solid rgba(255,59,92,0.25)',
                    color: '#FFB3C0',
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
                  placeholder="username / badge id"
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
                    InputProps={{
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton
                            onClick={() => setShowPassword(!showPassword)}
                            edge="end" size="small"
                            sx={{ color: 'rgba(229,231,235,0.4)' }}
                          >
                            {showPassword ? <VisibilityOff sx={{ fontSize: 17 }} />
                              : <Visibility sx={{ fontSize: 17 }} />}
                          </IconButton>
                        </InputAdornment>
                      ),
                    }}
                  />
                </Box>

                <Button
                  type="submit" fullWidth variant="contained"
                  disabled={loading}
                  startIcon={<LockOutlinedIcon sx={{ fontSize: 17 }} />}
                  sx={{
                    mt: 3.2, py: 1.15, fontWeight: 700, fontSize: 13,
                    letterSpacing: 1.2, borderRadius: 1.5,
                    backgroundColor: '#00D4FF', color: '#061018',
                    boxShadow: '0 0 22px rgba(0,212,255,0.32)',
                    transition: 'all 0.25s cubic-bezier(0.4,0,0.2,1)',
                    '&:hover': {
                      backgroundColor: '#25DDFF',
                      boxShadow: '0 0 32px rgba(0,212,255,0.55)',
                      transform: 'translateY(-1px)',
                    },
                  }}
                >
                  {loading ? 'AUTHENTICATING…' : 'AUTHENTICATE'}
                </Button>
              </form>

              <Typography sx={{ fontSize: 12.5, color: 'rgba(229,231,235,0.5)', mt: 2.5, textAlign: 'center' }}>
                No credentials issued?{' '}
                <RouterLink
                  to="/register"
                  style={{ color: '#00D4FF', textDecoration: 'none', fontWeight: 600 }}
                >
                  Request enrollment
                </RouterLink>
              </Typography>

              <Typography sx={{ fontSize: 12.5, color: 'rgba(229,231,235,0.5)', mt: 0.8, textAlign: 'center' }}>
                Awaiting authorization?{' '}
                <RouterLink
                  to="/status"
                  style={{ color: '#FFB020', textDecoration: 'none', fontWeight: 600 }}
                >
                  Track your request
                </RouterLink>
              </Typography>

              <Box
                sx={{
                  mt: 2.5, p: 1.4, borderRadius: 1.5,
                  backgroundColor: 'rgba(255,59,92,0.045)',
                  border: '1px solid rgba(255,59,92,0.16)',
                }}
              >
                <Typography
                  sx={{
                    fontSize: 10.5, lineHeight: 1.7, textAlign: 'center',
                    fontFamily: "'JetBrains Mono', monospace",
                    color: 'rgba(229,231,235,0.42)',
                  }}
                >
                  RESTRICTED SYSTEM · ALL ACCESS ATTEMPTS ARE LOGGED,
                  <br />TRACED AND REPORTED UNDER APPLICABLE CYBER LAW
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

export const consoleField = {
  '& .MuiOutlinedInput-root': {
    backgroundColor: 'rgba(255,255,255,0.03)',
    borderRadius: 1.5,
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: 13,
    transition: 'all 0.22s',
    '& fieldset': { borderColor: 'rgba(255,255,255,0.08)' },
    '&:hover fieldset': { borderColor: 'rgba(255,255,255,0.16)' },
    '&.Mui-focused': { backgroundColor: 'rgba(0,212,255,0.04)' },
    '&.Mui-focused fieldset': {
      borderColor: 'rgba(0,212,255,0.55)',
      borderWidth: '1px',
      boxShadow: '0 0 0 3px rgba(0,212,255,0.08)',
    },
  },
  '& input::placeholder': { color: 'rgba(229,231,235,0.25)', opacity: 1 },
};

export function FieldLabel({ text }) {
  return (
    <Typography
      sx={{
        fontSize: 10, letterSpacing: 1.4, mb: 0.7,
        fontFamily: "'JetBrains Mono', monospace",
        color: 'rgba(229,231,235,0.38)',
      }}
    >
      {text}
    </Typography>
  );
}

export function ConsoleBar() {
  return (
    <Box
      sx={{
        height: 34, display: 'flex', alignItems: 'center', gap: 2.5, px: 2.5,
        borderBottom: '1px solid rgba(255,255,255,0.05)',
        backgroundColor: 'rgba(11,15,26,0.9)',
        backdropFilter: 'blur(12px)',
        overflow: 'hidden', whiteSpace: 'nowrap',
      }}
    >
      <Dot color="#00E68A" label="NODE-01 ONLINE" />
      <Dot color="#00D4FF" label="TLS 1.3 CHANNEL" />
      <Dot color="#FFB020" label="SESSION MONITORED" />
      <Box sx={{ flexGrow: 1 }} />
      <Typography
        sx={{
          fontSize: 10, letterSpacing: 0.8,
          fontFamily: "'JetBrains Mono', monospace",
          color: 'rgba(229,231,235,0.3)',
          display: { xs: 'none', sm: 'block' },
        }}
      >
        CYBER CRIME BRANCH · AUTHORIZED DEPLOYMENT
      </Typography>
    </Box>
  );
}

export function Dot({ color, label }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.7 }}>
      <Box
        sx={{
          width: 6, height: 6, borderRadius: '50%',
          backgroundColor: color, boxShadow: `0 0 7px ${color}`,
          animation: 'blip 2.4s ease-in-out infinite',
          '@keyframes blip': { '0%,100%': { opacity: 1 }, '50%': { opacity: 0.3 } },
        }}
      />
      <Typography
        sx={{
          fontSize: 10, letterSpacing: 0.7,
          fontFamily: "'JetBrains Mono', monospace",
          color: 'rgba(229,231,235,0.45)',
        }}
      >
        {label}
      </Typography>
    </Box>
  );
}

export function MiniSpark({ label, value, delta, color, data, delay = 0, up = true }) {
  const max = Math.max(...data);
  return (
    <Box
      sx={{
        mb: 1.6,
        animation: `riseIn 0.5s ease ${delay}s both`,
        '@keyframes riseIn': {
          from: { opacity: 0, transform: 'translateY(10px)' },
          to: { opacity: 1, transform: 'translateY(0)' },
        },
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.6 }}>
        <Typography sx={{ fontSize: 11.5, color: 'rgba(229,231,235,0.6)', flexGrow: 1 }}>
          {label}
        </Typography>
        <Typography
          sx={{
            fontSize: 11.5, fontWeight: 600, color,
            fontFamily: "'JetBrains Mono', monospace",
          }}
        >
          {value}
        </Typography>
        <Typography
          sx={{
            fontSize: 10, ml: 0.8, fontFamily: "'JetBrains Mono', monospace",
            color: up ? '#00E68A' : '#FF3B5C',
          }}
        >
          {up ? '▲' : '▼'}{delta}
        </Typography>
      </Box>
      <Box sx={{ display: 'flex', alignItems: 'flex-end', gap: '2px', height: 22 }}>
        {data.map((v, i) => (
          <Box
            key={i}
            sx={{
              flex: 1, height: `${(v / max) * 100}%`, borderRadius: '1px',
              background: `linear-gradient(180deg, ${color} 0%, ${color}22 100%)`,
              transformOrigin: 'bottom',
              animation: `growBar 0.45s ease ${delay + i * 0.022}s both`,
              '@keyframes growBar': {
                from: { transform: 'scaleY(0)' }, to: { transform: 'scaleY(1)' },
              },
            }}
          />
        ))}
      </Box>
    </Box>
  );
}

export function TelemetryPanel() {
  return (
    <Box
      sx={{
        width: { xs: '100%', md: 300 },
        flexShrink: 0,
        p: 3,
        backgroundColor: 'rgba(255,255,255,0.014)',
        borderRight: { md: '1px solid rgba(255,255,255,0.06)' },
        borderBottom: { xs: '1px solid rgba(255,255,255,0.06)', md: 'none' },
        position: 'relative',
      }}
    >
      <Typography
        sx={{
          fontSize: 10, letterSpacing: 1.6, mb: 2,
          fontFamily: "'JetBrains Mono', monospace",
          color: 'rgba(229,231,235,0.35)',
        }}
      >
        LIVE SYSTEM TELEMETRY
      </Typography>

      <MiniSpark label="Capture throughput" value="1.24 Gb/s" delta="4%" color="#00D4FF" data={spark(0.5)} delay={0.05} />
      <MiniSpark label="Flows inspected" value="512.0 M" delta="7%" color="#00E68A" data={spark(0.8)} delay={0.12} />
      <MiniSpark label="Anomalies flagged" value="14.8 K" delta="3%" color="#FFB020" data={spark(1.1)} delay={0.19} up={false} />
      <MiniSpark label="Evidence sealed" value="2,417" delta="9%" color="#A855F7" data={spark(1.4)} delay={0.26} />

      <Box sx={{ height: '1px', backgroundColor: 'rgba(255,255,255,0.06)', my: 2.2 }} />

      <Typography
        sx={{
          fontSize: 10, letterSpacing: 1.6, mb: 1.4,
          fontFamily: "'JetBrains Mono', monospace",
          color: 'rgba(229,231,235,0.35)',
        }}
      >
        SUBSYSTEM STATUS
      </Typography>

      {[
        ['Capture engine', 'ACTIVE', '#00E68A'],
        ['Detection model', 'ACTIVE', '#00E68A'],
        ['Evidence vault', 'SEALED', '#00D4FF'],
        ['Audit logger', 'RECORDING', '#FFB020'],
      ].map(([k, v, c], i) => (
        <Box
          key={k}
          sx={{
            display: 'flex', alignItems: 'center', py: 0.75,
            borderBottom: i < 3 ? '1px solid rgba(255,255,255,0.035)' : 'none',
            animation: `riseIn 0.45s ease ${0.32 + i * 0.06}s both`,
          }}
        >
          <Typography sx={{ fontSize: 11.5, color: 'rgba(229,231,235,0.55)', flexGrow: 1 }}>
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