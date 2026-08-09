import { useState } from 'react';
import { Box, Typography, Tooltip } from '@mui/material';
import { useNavigate, useLocation } from 'react-router-dom';
import HomeOutlinedIcon from '@mui/icons-material/HomeOutlined';
import InsightsOutlinedIcon from '@mui/icons-material/InsightsOutlined';
import SensorsOutlinedIcon from '@mui/icons-material/SensorsOutlined';
import TravelExploreOutlinedIcon from '@mui/icons-material/TravelExploreOutlined';
import TimelineOutlinedIcon from '@mui/icons-material/TimelineOutlined';
import RuleFolderOutlinedIcon from '@mui/icons-material/RuleFolderOutlined';
import GavelOutlinedIcon from '@mui/icons-material/GavelOutlined';
import SettingsOutlinedIcon from '@mui/icons-material/SettingsOutlined';
import DeleteSweepOutlinedIcon from '@mui/icons-material/DeleteSweepOutlined';
import StorageOutlinedIcon from '@mui/icons-material/StorageOutlined';
import AccessTimeIcon from '@mui/icons-material/AccessTime';

const navItems = [
  { label: 'Home', icon: <HomeOutlinedIcon />, path: '/dashboard' },
  { label: 'Dashboard', icon: <InsightsOutlinedIcon />, path: '/dashboard', sub: ['Overview'] },
  { label: 'Capture', icon: <SensorsOutlinedIcon />, path: '/capture' },
  { label: 'Forensics', icon: <TravelExploreOutlinedIcon />, path: '/forensics' },
  { label: 'Sessions', icon: <TimelineOutlinedIcon />, path: '/sessions' },
  { label: 'Rules', icon: <RuleFolderOutlinedIcon />, path: '/rules' },
  { label: 'Evidence', icon: <GavelOutlinedIcon />, path: '/evidence' },
  { label: 'System', icon: <SettingsOutlinedIcon />, path: '/system' },
];

function Sidebar() {
  const navigate = useNavigate();
  const location = useLocation();
  const [active, setActive] = useState('Dashboard');

  return (
    <Box
      sx={{
        width: 210,
        flexShrink: 0,
        height: '100vh',
        position: 'sticky',
        top: 0,
        backgroundColor: '#0B0F1A',
        borderRight: '1px solid rgba(255,255,255,0.05)',
        display: 'flex',
        flexDirection: 'column',
        py: 2,
      }}
    >
      <Box sx={{ px: 2, flexGrow: 1 }}>
        {navItems.map((item, i) => {
          const isActive = active === item.label;
          return (
            <Box key={item.label}>
              <Box
                onClick={() => {
                  setActive(item.label);
                  navigate(item.path);
                }}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 1.5,
                  px: 1.5,
                  py: 1.1,
                  mb: 0.4,
                  borderRadius: 1.5,
                  cursor: 'pointer',
                  position: 'relative',
                  color: isActive ? '#00D4FF' : 'rgba(229,231,235,0.65)',
                  backgroundColor: isActive ? 'rgba(0,212,255,0.07)' : 'transparent',
                  transition: 'all 0.22s cubic-bezier(0.4,0,0.2,1)',
                  animation: `slideIn 0.4s ease ${i * 0.05}s both`,
                  '@keyframes slideIn': {
                    from: { opacity: 0, transform: 'translateX(-12px)' },
                    to: { opacity: 1, transform: 'translateX(0)' },
                  },
                  '&:hover': {
                    backgroundColor: 'rgba(255,255,255,0.04)',
                    color: '#E5E7EB',
                    transform: 'translateX(3px)',
                  },
                  '&::before': isActive
                    ? {
                        content: '""',
                        position: 'absolute',
                        left: -12,
                        top: '50%',
                        transform: 'translateY(-50%)',
                        width: 3,
                        height: 20,
                        borderRadius: 4,
                        backgroundColor: '#00D4FF',
                        boxShadow: '0 0 10px #00D4FF',
                      }
                    : {},
                }}
              >
                <Box sx={{ display: 'flex', '& svg': { fontSize: 19 } }}>{item.icon}</Box>
                <Typography sx={{ fontSize: 13.5, fontWeight: isActive ? 600 : 500 }}>
                  {item.label}
                </Typography>
              </Box>

              {item.sub && isActive && (
                <Box sx={{ pl: 5.5, pb: 0.5 }}>
                  {item.sub.map((s) => (
                    <Typography
                      key={s}
                      sx={{
                        fontSize: 12.5,
                        py: 0.6,
                        color: 'rgba(229,231,235,0.45)',
                        cursor: 'pointer',
                        transition: 'color 0.2s',
                        '&:hover': { color: '#00D4FF' },
                      }}
                    >
                      {s}
                    </Typography>
                  ))}
                </Box>
              )}
            </Box>
          );
        })}

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mt: 3, mb: 1.5 }}>
          <Box sx={{ flexGrow: 1, height: '1px', backgroundColor: 'rgba(255,255,255,0.07)' }} />
          <Typography sx={{ fontSize: 10.5, color: 'rgba(229,231,235,0.35)', letterSpacing: 1 }}>
            SHORTCUT
          </Typography>
          <Box sx={{ flexGrow: 1, height: '1px', backgroundColor: 'rgba(255,255,255,0.07)' }} />
        </Box>

        <ShortcutButton icon={<DeleteSweepOutlinedIcon />} label="Purge buffer" color="#00E68A" />
        <ShortcutButton icon={<StorageOutlinedIcon />} label="Rotate storage" color="#FF3B5C" />
      </Box>

      <Box sx={{ px: 2 }}>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            gap: 1.5,
            p: 1.5,
            borderRadius: 2,
            backgroundColor: 'rgba(255,255,255,0.03)',
            border: '1px solid rgba(255,255,255,0.06)',
          }}
        >
          <Box sx={{ flexGrow: 1 }}>
            <Typography sx={{ fontSize: 10.5, color: 'rgba(229,231,235,0.4)', letterSpacing: 0.8 }}>
              CAPTURE START
            </Typography>
            <Typography sx={{ fontSize: 11.5, fontFamily: "'JetBrains Mono', monospace", color: '#E5E7EB' }}>
              2026-08-02
            </Typography>
            <Typography sx={{ fontSize: 11.5, fontFamily: "'JetBrains Mono', monospace", color: '#E5E7EB', mb: 1 }}>
              09:14:07
            </Typography>
            <Typography sx={{ fontSize: 10.5, color: 'rgba(229,231,235,0.4)', letterSpacing: 0.8 }}>
              UPTIME
            </Typography>
            <Typography sx={{ fontSize: 11.5, fontFamily: "'JetBrains Mono', monospace", color: '#00E68A' }}>
              2d 04h 11m
            </Typography>
          </Box>
          <Box
            sx={{
              width: 38,
              height: 38,
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              border: '1.5px solid rgba(0,212,255,0.3)',
              color: '#00D4FF',
              animation: 'pulseRing 2.5s ease-in-out infinite',
              '@keyframes pulseRing': {
                '0%,100%': { boxShadow: '0 0 0 0 rgba(0,212,255,0.35)' },
                '50%': { boxShadow: '0 0 0 7px rgba(0,212,255,0)' },
              },
            }}
          >
            <AccessTimeIcon sx={{ fontSize: 19 }} />
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

function ShortcutButton({ icon, label, color }) {
  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1.3,
        py: 0.8,
        cursor: 'pointer',
        color: 'rgba(229,231,235,0.6)',
        transition: 'color 0.2s',
        '&:hover': { color: '#E5E7EB' },
      }}
    >
      <Box
        sx={{
          width: 26,
          height: 26,
          borderRadius: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: `${color}18`,
          color,
          '& svg': { fontSize: 16 },
        }}
      >
        {icon}
      </Box>
      <Typography sx={{ fontSize: 12.5 }}>{label}</Typography>
    </Box>
  );
}

export default Sidebar;