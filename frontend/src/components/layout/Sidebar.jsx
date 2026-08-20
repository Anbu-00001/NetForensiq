import { useEffect, useState } from 'react';
import { BANNER_HEIGHT } from './ClassificationBanner';
import { Box, Typography } from '@mui/material';
import { useNavigate, useLocation } from 'react-router-dom';
import InsightsOutlinedIcon from '@mui/icons-material/InsightsOutlined';
import RuleFolderOutlinedIcon from '@mui/icons-material/RuleFolderOutlined';
import GavelOutlinedIcon from '@mui/icons-material/GavelOutlined';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import HowToRegOutlinedIcon from '@mui/icons-material/HowToRegOutlined';
import UploadFileOutlinedIcon from '@mui/icons-material/UploadFileOutlined';
import FingerprintOutlinedIcon from '@mui/icons-material/FingerprintOutlined';

import EvidencePosture from './EvidencePosture';
import { DutyBoard, CaseDocket, CaptureHealth, IntelFeeds } from './SidebarPanels';
import { listSessions, unwrap } from '../../services/forensics';
import { PANEL, RULE, RULE_STRONG, CYAN, INK, GREY, PAPER } from '../../theme/tokens';
import { useCurrentUser } from '../../services/session';

// Only routes that exist. Navigation that leads nowhere reads as a mock-up,
// which is exactly the impression a forensic tool cannot afford to give.
const navItems = [
  { label: 'Dashboard', icon: <InsightsOutlinedIcon />, path: '/dashboard' },
  { label: 'Findings', icon: <RuleFolderOutlinedIcon />, path: '/detections' },
  { label: 'Evidence', icon: <GavelOutlinedIcon />, path: '/evidence' },
  { label: 'Import capture', icon: <UploadFileOutlinedIcon />, path: '/import' },
  // The access log the sign-in page promises. Administrators only, because it
  // names officers and source addresses — and because it is the one view where
  // a viewer account could learn which usernames are real.
  {
    label: 'Sign-in log',
    icon: <FingerprintOutlinedIcon />,
    path: '/sign-in-log',
    adminOnly: true,
  },
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
        width: { xs: 56, md: 232 },
        flexShrink: 0,
        height: `calc(100vh - ${BANNER_HEIGHT}px)`,
        position: 'sticky',
        top: `${BANNER_HEIGHT}px`,
        // Chrome, not content. The navigation used to be the same white as
        // the page it framed, separated only by a hairline the eye reads as an
        // accident — so the whole left edge floated. A tinted ground and a
        // definite border make the boundary deliberate, which is what every
        // government form does with its margin rule.
        backgroundColor: PANEL,
        borderRight: `1px solid ${RULE_STRONG}`,
        display: 'flex',
        flexDirection: 'column',
        py: 2,
        overflowY: 'auto',
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
                color: isActive ? CYAN : GREY,
                // Lifted to paper rather than tinted further: on a tinted rail
                // the selected item reads as the one closest to the reader.
                backgroundColor: isActive ? PAPER : 'transparent',
                border: `1px solid ${isActive ? RULE : 'transparent'}`,
                transition: 'all 0.22s cubic-bezier(0.4,0,0.2,1)',
                animation: `slideIn 0.4s ease ${i * 0.05}s both`,
                '@keyframes slideIn': {
                  from: { opacity: 0, transform: 'translateX(-12px)' },
                  to: { opacity: 1, transform: 'translateX(0)' },
                },
                '&:hover': {
                  backgroundColor: PAPER,
                  color: INK,
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
                      backgroundColor: CYAN,
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

      {/*
        Below the navigation because these are context rather than
        destinations, and in this order because it is the order an officer
        needs them in:

          what is owed        — the only block that can be acted on today;
          what is held        — and whether it can still be relied on;
          which cases         — and in what capacity, which decides who may
                                sign what;
          what is recording   — and whether there is room left to record into;
          what we know         — the indicator feeds, and how old they are;
          the capture window  — a detail about the exhibit on screen.

        A broken seal outranks a timestamp, and an overdue statutory duty
        outranks both.
      */}
      <Box sx={{ px: 2, display: { xs: 'none', md: 'block' } }}>
        <DutyBoard />
        <EvidencePosture />
        <CaseDocket />
        <CaptureHealth />
        <IntelFeeds />
        <CaptureWindow />
      </Box>

      {/* On the icon rail the same four states survive as dots. */}
      <Box sx={{ display: { xs: 'block', md: 'none' } }}>
        <EvidencePosture compact />
      </Box>
    </Box>
  );
}

export default Sidebar;
