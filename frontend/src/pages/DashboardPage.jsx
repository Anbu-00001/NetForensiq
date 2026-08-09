import { useState } from 'react';
import { Box, Typography } from '@mui/material';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import Sidebar from '../components/layout/Sidebar';
import TopBar from '../components/layout/TopBar';
import StatCard from '../components/dashboard/StatCard';
import ProtocolBubbles from '../components/dashboard/ProtocolBubbles';
import ProtocolRanking from '../components/dashboard/ProtocolRanking';
import HexHeatmap from '../components/dashboard/HexHeatmap';

const spark = (s) =>
  Array.from({ length: 22 }, (_, i) => 30 + Math.abs(Math.sin(i * s) * 60) + (i % 4) * 6);

const chartData = Array.from({ length: 20 }, (_, i) => ({
  day: `01/${String(i + 2).padStart(2, '0')}`,
  captured: 60 + Math.sin(i * 0.6) * 22 + i * 0.8,
  inspected: 44 + Math.cos(i * 0.5) * 16 + i * 0.5,
  flagged: 26 + Math.sin(i * 0.9) * 9,
  archived: 14 + Math.cos(i * 0.7) * 5,
}));

const ranges = ['Today', 'Week', 'Month'];

function DashboardPage() {
  const [range, setRange] = useState('Today');

  return (
    <Box sx={{ display: 'flex', backgroundColor: '#080B14', minHeight: '100vh' }}>
      <Sidebar />

      <Box sx={{ flexGrow: 1, minWidth: 0 }}>
        <TopBar />

        <Box sx={{ p: 2.5, display: 'flex', gap: 2.5, alignItems: 'flex-start' }}>
          {/* LEFT COLUMN */}
          <Box sx={{ flexGrow: 1, minWidth: 0 }}>
            <Box sx={{ display: 'flex', gap: 1.5, mb: 2.5, flexWrap: 'wrap' }}>
              <StatCard title="Captured" primary="627.16 M" secondary="1,233.23 M"
                color="#00D4FF" data={spark(0.5)} delay={0} />
              <StatCard title="Inspected" primary="512.04 M" secondary="998.71 M"
                color="#00E68A" data={spark(0.7)} delay={0.06} />
              <StatCard title="Flagged" primary="14.82 M" secondary="31.06 M"
                color="#FFB020" data={spark(0.9)} delay={0.12} />
              <StatCard title="Blocked" primary="2.41 M" secondary="6.55 M"
                color="#FF3B5C" data={spark(1.1)} delay={0.18} />
              <StatCard title="Archived" primary="88.30 M" secondary="140.12 M"
                color="#A855F7" data={spark(1.3)} delay={0.24} />
            </Box>

            <Box
              sx={{
                p: 2.5,
                borderRadius: 2,
                backgroundColor: 'rgba(255,255,255,0.02)',
                border: '1px solid rgba(255,255,255,0.06)',
                mb: 2.5,
              }}
            >
              <Typography sx={{ fontSize: 13, color: 'rgba(229,231,235,0.6)', mb: 0.5 }}>
                Overview of all traffic
              </Typography>

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 3, flexWrap: 'wrap', mb: 2 }}>
                <Typography
                  sx={{
                    fontSize: 34,
                    fontWeight: 800,
                    letterSpacing: -0.5,
                    background: 'linear-gradient(92deg,#FFFFFF 0%,#9FD9FF 100%)',
                    WebkitBackgroundClip: 'text',
                    WebkitTextFillColor: 'transparent',
                  }}
                >
                  627.16 M
                </Typography>

                <Box sx={{ display: 'flex', gap: 2.5 }}>
                  <Legend color="#00D4FF" label="Captured" />
                  <Legend color="#00E68A" label="Inspected" />
                  <Legend color="#FFB020" label="Flagged" />
                  <Legend color="#A855F7" label="Archived" />
                </Box>

                <Box sx={{ flexGrow: 1 }} />

                <Box sx={{ display: 'flex', gap: 0.5, p: 0.4, borderRadius: 1.5, backgroundColor: 'rgba(255,255,255,0.04)' }}>
                  {ranges.map((r) => (
                    <Box
                      key={r}
                      onClick={() => setRange(r)}
                      sx={{
                        px: 1.6, py: 0.5, borderRadius: 1, cursor: 'pointer', fontSize: 12,
                        fontWeight: 600,
                        color: range === r ? '#061018' : 'rgba(229,231,235,0.5)',
                        backgroundColor: range === r ? '#00D4FF' : 'transparent',
                        transition: 'all 0.25s',
                        boxShadow: range === r ? '0 0 14px rgba(0,212,255,0.4)' : 'none',
                        '&:hover': { color: range === r ? '#061018' : '#E5E7EB' },
                      }}
                    >
                      {r}
                    </Box>
                  ))}
                </Box>
              </Box>

              <ResponsiveContainer width="100%" height={260}>
                <AreaChart data={chartData} margin={{ top: 6, right: 6, left: -18, bottom: 0 }}>
                  <defs>
                    {[
                      ['gC', '#00D4FF'], ['gI', '#00E68A'],
                      ['gF', '#FFB020'], ['gA', '#A855F7'],
                    ].map(([id, c]) => (
                      <linearGradient key={id} id={id} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={c} stopOpacity={0.28} />
                        <stop offset="100%" stopColor={c} stopOpacity={0} />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
                  <XAxis dataKey="day" tick={{ fill: 'rgba(229,231,235,0.35)', fontSize: 10.5 }}
                    axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: 'rgba(229,231,235,0.35)', fontSize: 10.5 }}
                    axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(11,15,26,0.95)',
                      border: '1px solid rgba(0,212,255,0.25)',
                      borderRadius: 8, fontSize: 12,
                    }}
                  />
                  <Area type="monotone" dataKey="captured" stroke="#00D4FF" strokeWidth={2} fill="url(#gC)" />
                  <Area type="monotone" dataKey="inspected" stroke="#00E68A" strokeWidth={2} fill="url(#gI)" />
                  <Area type="monotone" dataKey="flagged" stroke="#FFB020" strokeWidth={2} fill="url(#gF)" />
                  <Area type="monotone" dataKey="archived" stroke="#A855F7" strokeWidth={2} fill="url(#gA)" />
                </AreaChart>
              </ResponsiveContainer>
            </Box>

            <Box sx={{ display: 'flex', gap: 2.5 }}>
              <HexHeatmap title="Inbound packet density" baseColor="#00A8FF" seed={7} />
              <HexHeatmap title="Outbound packet density" baseColor="#00E68A" seed={23} />
            </Box>
          </Box>

          {/* RIGHT COLUMN */}
          <Box sx={{ width: 300, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 2.5 }}>
            <ProtocolBubbles />
            <ProtocolRanking />
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

function Legend({ color, label }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.7 }}>
      <Box sx={{ width: 7, height: 7, borderRadius: '50%', backgroundColor: color, boxShadow: `0 0 6px ${color}` }} />
      <Typography sx={{ fontSize: 12, color: 'rgba(229,231,235,0.65)' }}>{label}</Typography>
    </Box>
  );
}

export default DashboardPage;