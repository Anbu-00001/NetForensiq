import { register } from '../services/auth';
import { useState } from 'react';
import {
  Box, Typography, TextField, Button, InputAdornment, IconButton,
  Alert, Grow, MenuItem,
} from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import BadgeOutlinedIcon from '@mui/icons-material/BadgeOutlined';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import PersonAddAltIcon from '@mui/icons-material/PersonAddAlt';
import { ConsoleBar, FieldLabel, Dot } from './LoginPage';
import { consoleField } from '../theme/formStyles';

const roles = [
  { value: 'investigator', label: 'Investigator' },
  { value: 'viewer', label: 'Viewer' },
];

// Only the stages that exist. "Identity verification" was advertised here and
// on the status page; nothing in the system performs it.
const pipeline = [
  ['01', 'Submit credentials', '#00D4FF', 'YOU ARE HERE'],
  ['02', 'Administrator review', 'rgba(229,231,235,0.3)', 'PENDING'],
  ['03', 'Access granted', 'rgba(229,231,235,0.3)', 'LOCKED'],
];

function RegisterPage() {
  const [formData, setFormData] = useState({
    fullName: '', badgeId: '', email: '', department: '',
    role: '', username: '', password: '', confirmPassword: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleChange = (f) => (e) => setFormData({ ...formData, [f]: e.target.value });

  const handleSubmit = async (e) => {
  e.preventDefault();
  setError('');
  setSuccess(false);

  const v = Object.values(formData);
  if (v.some((x) => !x)) { setError('All fields are required.'); return; }
  if (formData.password !== formData.confirmPassword) {
    setError('Passphrases do not match.'); return;
  }
  if (formData.password.length < 8) {
    setError('Passphrase must be at least 8 characters.'); return;
  }

  setLoading(true);
  try {
    await register({
      username: formData.username,
      email: formData.email,
      first_name: formData.fullName,
      badge_id: formData.badgeId,
      department: formData.department,
      role: formData.role,
      password: formData.password,
      confirm_password: formData.confirmPassword,
    });
    setSuccess(true);
    setFormData({
      fullName: '', badgeId: '', email: '', department: '',
      role: '', username: '', password: '', confirmPassword: '',
    });
  } catch (err) {
    const data = err.response?.data;
    let msg = 'Enrollment request failed.';
    if (data && typeof data === 'object') {
      const firstKey = Object.keys(data)[0];
      const firstVal = data[firstKey];
      msg = Array.isArray(firstVal) ? `${firstKey}: ${firstVal[0]}` : String(firstVal);
    }
    setError(msg);
  } finally {
    setLoading(false);
  }
};

  return (
    <Box sx={{ minHeight: '100vh', backgroundColor: '#080B14', display: 'flex', flexDirection: 'column' }}>
      <ConsoleBar />

      <Box
        sx={{
          flexGrow: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
          px: 2, py: 4, position: 'relative',
          backgroundImage: `
            linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px)
          `,
          backgroundSize: '46px 46px',
        }}
      >
        <Box
          sx={{
            position: 'absolute', width: 820, height: 820, borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(168,85,247,0.06) 0%, transparent 68%)',
            top: '45%', left: '50%', transform: 'translate(-50%,-50%)', pointerEvents: 'none',
          }}
        />

        <Grow in appear timeout={620}>
          <Box
            sx={{
              display: 'flex', flexDirection: { xs: 'column', md: 'row' },
              width: '100%', maxWidth: 940, borderRadius: 2, overflow: 'hidden',
              backgroundColor: 'rgba(255,255,255,0.02)',
              border: '1px solid rgba(255,255,255,0.07)',
              boxShadow: '0 24px 70px -20px rgba(0,0,0,0.75)',
              position: 'relative', zIndex: 1,
            }}
          >
            {/* ── PIPELINE SIDE ── */}
            <Box
              sx={{
                width: { xs: '100%', md: 288 }, flexShrink: 0, p: 3,
                backgroundColor: 'rgba(255,255,255,0.014)',
                borderRight: { md: '1px solid rgba(255,255,255,0.06)' },
                borderBottom: { xs: '1px solid rgba(255,255,255,0.06)', md: 'none' },
              }}
            >
              <Typography
                sx={{
                  fontSize: 10, letterSpacing: 1.6, mb: 2.5,
                  fontFamily: "'JetBrains Mono', monospace",
                  color: 'rgba(229,231,235,0.55)',
                }}
              >
                ENROLLMENT PIPELINE
              </Typography>

              {pipeline.map(([n, label, color, state], i) => (
                <Box
                  key={n}
                  sx={{
                    display: 'flex', gap: 1.6, pb: 2.4, position: 'relative',
                    animation: `riseIn 0.5s ease ${0.08 + i * 0.09}s both`,
                    '@keyframes riseIn': {
                      from: { opacity: 0, transform: 'translateY(10px)' },
                      to: { opacity: 1, transform: 'translateY(0)' },
                    },
                    '&::before': i < pipeline.length - 1 ? {
                      content: '""', position: 'absolute', left: 13, top: 30,
                      width: '1px', height: 'calc(100% - 30px)',
                      backgroundColor: 'rgba(255,255,255,0.08)',
                    } : {},
                  }}
                >
                  <Box
                    sx={{
                      width: 27, height: 27, flexShrink: 0, borderRadius: '50%',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 10.5, fontWeight: 700,
                      fontFamily: "'JetBrains Mono', monospace",
                      color: i === 0 ? '#061018' : 'rgba(229,231,235,0.4)',
                      backgroundColor: i === 0 ? '#00D4FF' : 'rgba(255,255,255,0.05)',
                      border: i === 0 ? 'none' : '1px solid rgba(255,255,255,0.09)',
                      boxShadow: i === 0 ? '0 0 16px rgba(0,212,255,0.45)' : 'none',
                      zIndex: 1,
                    }}
                  >
                    {n}
                  </Box>
                  <Box sx={{ pt: 0.2 }}>
                    <Typography sx={{ fontSize: 12.5, fontWeight: 500, color: i === 0 ? '#E5E7EB' : 'rgba(229,231,235,0.5)' }}>
                      {label}
                    </Typography>
                    <Typography
                      sx={{
                        fontSize: 9.5, letterSpacing: 0.9, mt: 0.3,
                        fontFamily: "'JetBrains Mono', monospace", color,
                      }}
                    >
                      {state}
                    </Typography>
                  </Box>
                </Box>
              ))}

              <Box sx={{ height: '1px', backgroundColor: 'rgba(255,255,255,0.06)', my: 1.5 }} />

              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.2, mt: 2 }}>
                <Dot color="#FFB020" label="MANUAL REVIEW REQUIRED" />
                <Dot color="#FF3B5C" label="FALSE DECLARATION = OFFENCE" />
              </Box>
            </Box>

            {/* ── FORM SIDE ── */}
            <Box sx={{ flex: 1, p: { xs: 3, sm: 4 }, minWidth: 0 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.4, mb: 0.6 }}>
                <Box
                  sx={{
                    width: 38, height: 38, borderRadius: 1.5,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    backgroundColor: 'rgba(0,212,255,0.09)',
                    border: '1px solid rgba(0,212,255,0.28)', color: '#00D4FF',
                  }}
                >
                  <BadgeOutlinedIcon sx={{ fontSize: 21 }} />
                </Box>
                <Box>
                  <Typography sx={{ fontSize: 17, fontWeight: 800, letterSpacing: 1.4 }}>
                    PERSONNEL ENROLLMENT
                  </Typography>
                  <Typography
                    sx={{
                      fontSize: 10.5, letterSpacing: 0.8,
                      fontFamily: "'JetBrains Mono', monospace",
                      color: 'rgba(229,231,235,0.55)',
                    }}
                  >
                    NETFORENSIQ · CYBER CRIME BRANCH
                  </Typography>
                </Box>
              </Box>

              <Box sx={{ height: '1px', backgroundColor: 'rgba(255,255,255,0.07)', my: 2.4 }} />

              {error && (
                <Alert
                  severity="error"
                  sx={{
                    mb: 2, fontSize: 12.5,
                    backgroundColor: 'rgba(255,59,92,0.08)',
                    border: '1px solid rgba(255,59,92,0.25)', color: '#FFB3C0',
                  }}
                >
                  {error}
                </Alert>
              )}
              {success && (
                <Alert
                  severity="success"
                  sx={{
                    mb: 2, fontSize: 12.5,
                    backgroundColor: 'rgba(0,230,138,0.07)',
                    border: '1px solid rgba(0,230,138,0.25)', color: '#8FF3C8',
                  }}
                >
                  Request logged. Awaiting administrator authorization.
                </Alert>
              )}

              <form onSubmit={handleSubmit}>
                <SectionRule text="IDENTITY RECORD" />

                <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' }, gap: 2 }}>
                  <Box>
                    <FieldLabel text="FULL NAME" />
                    <TextField fullWidth size="small" sx={consoleField} placeholder="as per service record"
                      value={formData.fullName} onChange={handleChange('fullName')} />
                  </Box>
                  <Box>
                    <FieldLabel text="BADGE / EMPLOYEE ID" />
                    <TextField fullWidth size="small" sx={consoleField} placeholder="e.g. INV-0042"
                      value={formData.badgeId} onChange={handleChange('badgeId')} />
                  </Box>
                  <Box>
                    <FieldLabel text="OFFICIAL EMAIL" />
                    <TextField fullWidth size="small" type="email" sx={consoleField} placeholder="name@dept.gov.in"
                      value={formData.email} onChange={handleChange('email')} />
                  </Box>
                  <Box>
                    <FieldLabel text="DEPARTMENT / UNIT" />
                    <TextField fullWidth size="small" sx={consoleField} placeholder="e.g. Cyber Crime Unit A"
                      value={formData.department} onChange={handleChange('department')} />
                  </Box>
                </Box>

                <Box sx={{ mt: 2 }}>
                  <FieldLabel text="REQUESTED CLEARANCE LEVEL" />
                  <TextField
                    select fullWidth size="small" sx={consoleField}
                    value={formData.role} onChange={handleChange('role')}
                    slotProps={{ select: {
                      displayEmpty: true,
                      renderValue: (v) => v
                        ? roles.find((r) => r.value === v)?.label
                        : <span style={{ color: 'rgba(229,231,235,0.55)' }}>select clearance…</span>,
                      MenuProps: {
                        PaperProps: {
                          sx: {
                            backgroundColor: '#0D1220',
                            border: '1px solid rgba(255,255,255,0.09)',
                            '& .MuiMenuItem-root': { fontSize: 13 },
                          },
                        },
                      },
                    } }}
                  >
                    {roles.map((o) => (
                      <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
                    ))}
                  </TextField>
                  <Typography sx={{ fontSize: 10.5, color: 'rgba(229,231,235,0.55)', mt: 0.6 }}>
                    Administrator clearance cannot be self-requested.
                  </Typography>
                </Box>

                <SectionRule text="ACCESS CREDENTIALS" sx={{ mt: 3 }} />

                <Box>
                  <FieldLabel text="USERNAME" />
                  <TextField fullWidth size="small" sx={consoleField} placeholder="lowercase, no spaces"
                    value={formData.username} onChange={handleChange('username')} />
                </Box>

                <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' }, gap: 2, mt: 2 }}>
                  <Box>
                    <FieldLabel text="PASSPHRASE" />
                    <TextField
                      fullWidth size="small" sx={consoleField} placeholder="min. 8 characters"
                      type={showPassword ? 'text' : 'password'}
                      value={formData.password} onChange={handleChange('password')}
                      slotProps={{ input: {
                        endAdornment: (
                          <InputAdornment position="end">
                            <IconButton size="small" onClick={() => setShowPassword(!showPassword)}
                              sx={{ color: 'rgba(229,231,235,0.55)' }}>
                              {showPassword ? <VisibilityOff sx={{ fontSize: 17 }} /> : <Visibility sx={{ fontSize: 17 }} />}
                            </IconButton>
                          </InputAdornment>
                        ),
                      } }}
                    />
                  </Box>
                  <Box>
                    <FieldLabel text="CONFIRM PASSPHRASE" />
                    <TextField
                      fullWidth size="small" sx={consoleField} placeholder="re-enter"
                      type={showConfirm ? 'text' : 'password'}
                      value={formData.confirmPassword} onChange={handleChange('confirmPassword')}
                      slotProps={{ input: {
                        endAdornment: (
                          <InputAdornment position="end">
                            <IconButton size="small" onClick={() => setShowConfirm(!showConfirm)}
                              sx={{ color: 'rgba(229,231,235,0.55)' }}>
                              {showConfirm ? <VisibilityOff sx={{ fontSize: 17 }} /> : <Visibility sx={{ fontSize: 17 }} />}
                            </IconButton>
                          </InputAdornment>
                        ),
                      } }}
                    />
                  </Box>
                </Box>

                <Button
                  type="submit" fullWidth variant="contained"
                  disabled={loading}
                  startIcon={<PersonAddAltIcon sx={{ fontSize: 17 }} />}
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
                  {loading ? 'SUBMITTING…' : 'SUBMIT FOR AUTHORIZATION'}
                </Button>
              </form>

              <Typography sx={{ fontSize: 12.5, color: 'rgba(229,231,235,0.55)', mt: 2.4, textAlign: 'center' }}>
                Already enrolled?{' '}
                <RouterLink to="/login" style={{ color: '#00D4FF', textDecoration: 'none', fontWeight: 600 }}>
                  Return to terminal
                </RouterLink>
              </Typography>

              <Typography sx={{ fontSize: 12.5, color: 'rgba(229,231,235,0.55)', mt: 0.8, textAlign: 'center' }}>
                Already submitted?{' '}
                <RouterLink to="/status" style={{ color: '#FFB020', textDecoration: 'none', fontWeight: 600 }}>
                  Track your request
                </RouterLink>
              </Typography>
            </Box>
          </Box>
        </Grow>
      </Box>
    </Box>
  );
}

function SectionRule({ text, sx }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.4, mb: 1.8, ...sx }}>
      <Typography
        sx={{
          fontSize: 10, letterSpacing: 1.5, whiteSpace: 'nowrap',
          fontFamily: "'JetBrains Mono', monospace", color: '#00D4FF',
        }}
      >
        {text}
      </Typography>
      <Box sx={{ flexGrow: 1, height: '1px', background: 'linear-gradient(90deg, rgba(0,212,255,0.28), transparent)' }} />
    </Box>
  );
}

export default RegisterPage;