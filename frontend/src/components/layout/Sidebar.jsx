import { useEffect, useState } from 'react';
import { BANNER_HEIGHT } from './ClassificationBanner';
import { Box, Typography } from '@mui/material';
import { useNavigate, useLocation } from 'react-router-dom';
import InsightsOutlinedIcon from '@mui/icons-material/InsightsOutlined';
import RuleFolderOutlinedIcon from '@mui/icons-material/RuleFolderOutlined';
import GavelOutlinedIcon from '@mui/icons-material/GavelOutlined';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import HowToRegOutlinedIcon from '@mui/icons-material/HowToRegOutlined';

import { listSessions, unwrap } from '../../services/forensics';
import { useCurrentUser } from '../../services/session';

// Only routes that exist. Navigation that leads nowhere reads as a mock-up,
// which is exactly the impression a forensic tool cannot afford to give.
const navItems = [
  { label: 'Dashboard', icon: <InsightsOutlinedIcon />, path: '/dashboard' },
  { label: 'Findings', icon: <RuleFolderOutlinedIcon />, path: '/detections' },
  { label: 'Evidence', icon: <GavelOutlinedIcon />, path: '/evidence' },
  // Administrators only. Shown to nobody else, because a navigation entry
  // leading to "you are not cleared for this" is a worse answer than no entry.
  {
    label: 'Approvals',
    icon: <HowToRegOutlinedIcon />,
    path: '/approvals',
    adminOnly: true,
  },
];

/**
 * The capture window of the most recent session.
 *
 * This block previously showed a hardcoded start of 2026-08-02 09:14:07 and an
 * "UPTIME" of 2d 04h 11m — neither of which came from anywhere. It also
 * carried "Purge buffer" and "Rotate storage" buttons wired to nothing, for
 * destructive operations this tool cannot perform on evidence. Both are gone
 * for the same reason the "Blocked" and "Archived" cards were removed from the
 * dashboard: the interface must not imply capabilities that do not exist.
 *
 * "Uptime" is also the wrong idea for imported evidence. What matters is the
 * span the capture covers, which is a property of the exhibit rather than of
 * our process, so that is what is shown.
 */
function CaptureWindow() {
  const [session, setSession] = useState(null);

  useEffect(() => {
    let cancelled = false;
    listSessions()
      .then((data) => {
        if (cancelled) return;
        const list = unwrap(data);
        setSession(list.length ? list[0] : null);
      })
      .catch(() => setSession(null));
    return () => { cancelled = true; };
  }, []);

  if (!session?.capture_start) {
    return (
      <Box sx={{
        p: 1.5, borderRadius: 2,
        backgroundColor: '#F4F5F7',
        border: '1px solid #E2E5E9',
      }}>
        <Typography sx={{ fontSize: 10.5, color: '#5A6068', letterSpacing: 0.8 }}>
          CAPTURE WINDOW
        </Typography>
        <Typography sx={{ fontSize: 11.5, color: '#5A6068' }}>
          No capture loaded
        </Typography>
      </Box>
    );
  }

  const start = new Date(session.capture_start);
  const end = session.capture_end ? new Date(session.capture_end) : null;
  const spanMs = end ? end - start : 0;

  const span = (() => {
    if (!spanMs) return '—';
    const s = Math.floor(spanMs / 1000);
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d) return `${d}d ${String(h).padStart(2, '0')}h ${String(m).padStart(2, '0')}m`;
    if (h) return `${h}h ${String(m).padStart(2, '0')}m`;
    if (m) return `${m}m ${String(s % 60).padStart(2, '0')}s`;
    return `${s}s`;
  })();

  const pad = (n) => String(n).padStart(2, '0');

  return (
    <Box sx={{
      display: 'flex', alignItems: 'center', gap: 1.5, p: 1.5, borderRadius: 2,
      backgroundColor: '#F4F5F7',
      border: '1px solid #E2E5E9',
    }}>
      <Box sx={{ flexGrow: 1, minWidth: 0 }}>
        <Typography sx={{ fontSize: 10.5, color: '#5A6068', letterSpacing: 0.8 }}>
          CAPTURE START
        </Typography>
        <Typography sx={{
          fontSize: 11.5, fontFamily: "'JetBrains Mono', monospace", color: '#111315',
        }}>
          {`${start.getFullYear()}-${pad(start.getMonth() + 1)}-${pad(start.getDate())}`}
        </Typography>
        <Typography sx={{
          fontSize: 11.5, fontFamily: "'JetBrains Mono', monospace", color: '#111315', mb: 1,
        }}>
          {`${pad(start.getHours())}:${pad(start.getMinutes())}:${pad(start.getSeconds())}`}
        </Typography>
        <Typography sx={{ fontSize: 10.5, color: '#5A6068', letterSpacing: 0.8 }}>
          SPAN COVERED
        </Typography>
        <Typography sx={{
          fontSize: 11.5, fontFamily: "'JetBrains Mono', monospace", color: '#1B6E3C',
        }}>
          {span}
        </Typography>
      </Box>
      <Box sx={{
        width: 38, height: 38, borderRadius: '50%', flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        border: '1.5px solid rgba(7,110,124,0.35)', color: '#076E7C',
      }}>
        <AccessTimeIcon sx={{ fontSize: 19 }} />
      </Box>
    </Box>
  );
}

function Sidebar() {
  const navigate = useNavigate();
  const location = useLocation();
  const user = useCurrentUser();
  const isAdmin = user?.is_superuser || user?.role === 'admin';

  return (
    <Box
      sx={{
        // An icon rail on a phone, the full sidebar on a laptop. A fixed
        // 210px against a 390px viewport left 180px for the content and the
        // page scrolled sideways — which on a tool an officer may open on a
        // phone is not a cosmetic problem.
        width: { xs: 56, md: 210 },
        flexShrink: 0,
        height: `calc(100vh - ${BANNER_HEIGHT}px)`,
        position: 'sticky',
        top: `${BANNER_HEIGHT}px`,
        backgroundColor: '#FFFFFF',
        borderRight: '1px solid #ECEEF1',
        display: 'flex',
        flexDirection: 'column',
        py: 2,
      }}
    >
      <Box sx={{ px: { xs: 0.75, md: 2 }, flexGrow: 1 }}>
        {navItems.filter((item) => !item.adminOnly || isAdmin).map((item, i) => {
          // Derived from the URL rather than held in state, so a direct visit
          // or a back-button navigation highlights the right entry.
          const isActive = location.pathname.startsWith(item.path);
          return (
            <Box
              key={item.label}
              onClick={() => navigate(item.path)}
              sx={{
                display: 'flex',
                alignItems: 'center',
                gap: 1.5,
                justifyContent: { xs: 'center', md: 'flex-start' },
                px: { xs: 0.5, md: 1.5 },
                py: 1.1,
                mb: 0.4,
                borderRadius: 1.5,
                cursor: 'pointer',
                position: 'relative',
                color: isActive ? '#076E7C' : '#5A6068',
                backgroundColor: isActive ? 'rgba(7,110,124,0.09)' : 'transparent',
                transition: 'all 0.22s cubic-bezier(0.4,0,0.2,1)',
                animation: `slideIn 0.4s ease ${i * 0.05}s both`,
                '@keyframes slideIn': {
                  from: { opacity: 0, transform: 'translateX(-12px)' },
                  to: { opacity: 1, transform: 'translateX(0)' },
                },
                '&:hover': {
                  backgroundColor: '#F4F5F7',
                  color: '#111315',
                  transform: 'translateX(3px)',
                },
                '&::before': isActive
                  ? {
                      content: '""',
                      position: 'absolute',
                      left: -12,
                      top: '50%',
                      width: 3,
                      height: 20,
                      borderRadius: 4,
                      backgroundColor: '#076E7C',
                    }
                  : {},
              }}
            >
              <Box sx={{ display: 'flex', '& svg': { fontSize: 19 } }}>{item.icon}</Box>
              <Typography sx={{
                fontSize: 13.5, fontWeight: isActive ? 600 : 500,
                display: { xs: 'none', md: 'block' },
              }}>
                {item.label}
              </Typography>
            </Box>
          );
        })}
      </Box>

      {/* The capture window needs room for two timestamps; on a rail it
          would truncate into something unreadable, so it is hidden rather
          than shown badly. */}
      <Box sx={{ px: 2, display: { xs: 'none', md: 'block' } }}>
        <CaptureWindow />
      </Box>
    </Box>
  );
}

export default Sidebar;
