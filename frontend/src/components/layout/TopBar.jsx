import { useState } from 'react';
import { Menu, MenuItem } from '@mui/material';
import LogoutIcon from '@mui/icons-material/Logout';
import { useNavigate } from 'react-router-dom';
import { logout, getCurrentUser } from '../../services/auth';
import { Box, Typography, InputBase, Avatar } from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import { BANNER_HEIGHT } from './ClassificationBanner';
import ShieldOutlinedIcon from '@mui/icons-material/ShieldOutlined';

function TopBar() {
  const [anchorEl, setAnchorEl] = useState(null);
  const [term, setTerm] = useState('');
  const navigate = useNavigate();
const user = getCurrentUser();
const initials = user?.first_name
  ? user.first_name.split(' ').map((w) => w[0]).join('').slice(0, 2).toUpperCase()
  : user?.username?.slice(0, 2).toUpperCase() || 'NF';
  return (
    <Box
      sx={{
        height: 58,
        display: 'flex',
        alignItems: 'center',
        // The bar held a wordmark, a subtitle, a fixed-width search box and an
        // account block, none of which could shrink; on a 390px screen the
        // page scrolled sideways by nearly 100px. Nothing is removed — the
        // pieces that carry no information at small sizes step aside, and the
        // rest are allowed to shrink.
        px: { xs: 1.5, md: 3 },
        gap: { xs: 1, md: 2 },
        minWidth: 0,
        position: 'sticky',
        top: `${BANNER_HEIGHT}px`,
        zIndex: 20,
        // Matches the sidebar: chrome is tinted and bounded, content is paper.
        borderBottom: '1px solid #C7CCD2',
        backgroundColor: '#F4F5F7',
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexShrink: 0 }}>
        <ShieldOutlinedIcon sx={{ color: '#076E7C', fontSize: 24 }} />
        <Typography sx={{
          fontWeight: 800, letterSpacing: 2.5, fontSize: 15,
          display: { xs: 'none', sm: 'block' },
        }}>
          NETFORENSIQ
        </Typography>
      </Box>

      <Box sx={{
        width: '1px', height: 22, backgroundColor: '#E2E5E9',
        display: { xs: 'none', md: 'block' },
      }} />

      <Typography sx={{
        fontSize: 14, color: '#2B3138',
        display: { xs: 'none', md: 'block' },
      }}>
        Packet Forensics Console
      </Typography>

      <Box sx={{ flexGrow: 1, minWidth: 0 }} />

      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          px: 1.5,
          py: 0.6,
          // Shrinks with the bar rather than forcing it wider.
          flex: { xs: '1 1 0', sm: '0 0 auto' },
          width: { sm: 240 },
          minWidth: 0,
          borderRadius: 1.5,
          backgroundColor: '#F4F5F7',
          border: '1px solid transparent',
          transition: 'all 0.25s',
          '&:focus-within': {
            borderColor: 'rgba(7,110,124,0.45)',
            backgroundColor: 'rgba(7,110,124,0.07)',
            width: { xs: 150, sm: 300 },
          },
        }}
      >
        <SearchIcon sx={{ fontSize: 17, color: '#5A6068' }} />
        <InputBase
          placeholder="Search IP, domain, rule…"
          value={term}
          onChange={(e) => setTerm(e.target.value)}
          onKeyDown={(e) => {
            if (e.key !== 'Enter') return;
            const q = term.trim();
            navigate(q ? `/detections?q=${encodeURIComponent(q)}` : '/detections');
          }}
          sx={{
            fontSize: 13,
            color: '#111315',
            width: '100%',
            fontFamily: "'JetBrains Mono', monospace",
          }}
        />
      </Box>


      <Box
        onClick={(e) => setAnchorEl(e.currentTarget)}
        sx={{
          display: 'flex', alignItems: 'center', gap: 1.2, cursor: 'pointer',
          px: 1, py: 0.5, borderRadius: 1.5, transition: 'background 0.2s',
          '&:hover': { backgroundColor: '#F4F5F7' },
        }}
      >
        <Avatar
          sx={{
            width: 32, height: 32, fontSize: 12, fontWeight: 700,
            backgroundColor: 'rgba(7,110,124,0.16)', color: '#076E7C',
            border: '1px solid rgba(7,110,124,0.34)',
          }}
        >
          {initials}
        </Avatar>
        <Box sx={{ display: { xs: 'none', sm: 'block' } }}>
          <Typography sx={{ fontSize: 12, fontWeight: 600, lineHeight: 1.2, textTransform: 'capitalize' }}>
            {/* 'Operator' is not one of the backend's roles (admin /
                investigator / viewer). A user whose role fails to load was
                shown as holding a role that does not exist; the fields either
                side of this one already use an em dash. */}
            {user?.role || '—'}
          </Typography>
          <Typography sx={{ fontSize: 10.5, color: '#5A6068', lineHeight: 1.2 }}>
            {user?.username || '—'}
          </Typography>
        </Box>
      </Box>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
        slotProps={{
          paper: {
            sx: {
              mt: 1, minWidth: 180,
              backgroundColor: '#F4F5F7',
              border: '1px solid #E2E5E9',
              borderRadius: 1.5,
            },
          },
        }}
      >
        <Box sx={{ px: 2, py: 1.2, borderBottom: '1px solid #E2E5E9' }}>
          <Typography sx={{ fontSize: 9.5, letterSpacing: 1, fontFamily: "'JetBrains Mono', monospace", color: '#5A6068' }}>
            BADGE ID
          </Typography>
          <Typography sx={{ fontSize: 12, fontFamily: "'JetBrains Mono', monospace", color: '#111315' }}>
            {user?.badge_id || '—'}
          </Typography>
        </Box>
        <MenuItem
          onClick={logout}
          sx={{ fontSize: 13, gap: 1.2, color: '#B3261E', mt: 0.5, '&:hover': { backgroundColor: 'rgba(179,38,30,0.07)' } }}
        >
          <LogoutIcon sx={{ fontSize: 17 }} />
          Terminate session
        </MenuItem>
      </Menu>
    </Box>
  );
}

export default TopBar;