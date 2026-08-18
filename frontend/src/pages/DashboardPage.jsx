import { useEffect, useState } from 'react';
import { Box, Typography, MenuItem, Select, CircularProgress, Button, Alert } from '@mui/material';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import { describeError } from '../services/api';
import Sidebar from '../components/layout/Sidebar';
import TopBar from '../components/layout/TopBar';
import StatCard from '../components/dashboard/StatCard';
import ProtocolBubbles from '../components/dashboard/ProtocolBubbles';
import ProtocolRanking from '../components/dashboard/ProtocolRanking';
import SeverityBreakdown from '../components/dashboard/SeverityBreakdown';
import {
  listSessions, getSessionSummary, getSessionTimeline, analyseSession,
  unwrap, formatBytes, formatCount,
} from '../services/forensics';

const PANEL = {
  p: 2.5,
  borderRadius: 2,
  backgroundColor: 'rgba(255,255,255,0.02)',
  border: '1px solid rgba(255,255,255,0.06)',
};

function DashboardPage() {
  const [sessions, setSessions] = useState([]);
  const [sessionId, setSessionId] = useState('');
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [bucketSeconds, setBucketSeconds] = useState(null);
  const [loading, setLoading] = useState(true);
  const [analysing, setAnalysing] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    listSessions()
      .then((data) => {
        const list = unwrap(data);
        setSessions(list);
        if (list.length) setSessionId(list[0].id);
        else setLoading(false);
      })
      // describeError distinguishes "the backend is down" from "you are being
      // rate limited" — telling an officer to check the server when the server
      // is fine and throttling them sends them the wrong way.
      .catch((err) => {
        setError(describeError(err, 'Could not reach the API. Is the backend running?'));
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    if (!sessionId) return undefined;

    // `loading` is set from the promise chain rather than synchronously at
    // the top of the effect: a synchronous setState here schedules a second
    // render before the request has even been issued.
    let current = true;
    Promise.all([getSessionSummary(sessionId), getSessionTimeline(sessionId)])
      .then(([s, t]) => {
        if (!current) return;
        setSummary(s);
        setTimeline(t.series ?? []);
        setBucketSeconds(t.bucket_seconds ?? null);
        setError('');
      })
      .catch((err) => { if (current) setError(describeError(err, 'Failed to load session data.')); })
      .finally(() => { if (current) setLoading(false); });

    // Switching sessions while a request is in flight would otherwise let the
    // slower response overwrite the newer one.
    return () => { current = false; };
  }, [sessionId]);

  const runAnalysis = async () => {
    setAnalysing(true);
    try {
      await analyseSession(sessionId);
      const [s, t] = await Promise.all([
        getSessionSummary(sessionId), getSessionTimeline(sessionId),
      ]);
      setSummary(s);
      setTimeline(t.series ?? []);
    } catch {
      setError('Analysis failed.');
    } finally {
      setAnalysing(false);
    }
  };

  const totals = summary?.totals;
  const severities = summary?.detections_by_severity ?? [];

  return (
    <Box sx={{ display: 'flex', backgroundColor: '#080B14', minHeight: '100vh' }}>
      <Sidebar />
      <Box sx={{ flexGrow: 1, minWidth: 0 }}>
        <TopBar />

        <Box sx={{ p: 2.5 }}>
          {/* Session selector — the dashboard always describes one capture */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2.5, flexWrap: 'wrap' }}>
            <Typography sx={{ fontSize: 13, color: 'rgba(229,231,235,0.6)' }}>
              Capture session
            </Typography>
            <Select
              size="small"
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              sx={{
                minWidth: { xs: 0, sm: 280 }, maxWidth: '100%',
                color: '#E5E7EB', fontSize: 13,
                backgroundColor: 'rgba(255,255,255,0.04)',
                '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(255,255,255,0.12)' },
                '& .MuiSvgIcon-root': { color: 'rgba(229,231,235,0.55)' },
              }}
            >
              {sessions.map((s) => (
                <MenuItem key={s.id} value={s.id}>
                  #{s.id} · {s.name} · {formatCount(s.packet_count)} pkts
                </MenuItem>
              ))}
            </Select>
            <Button
              size="small" variant="outlined" onClick={runAnalysis}
              disabled={!sessionId || analysing}
              sx={{
                borderColor: 'rgba(0,212,255,0.4)', color: '#00D4FF', fontSize: 12,
                '&:hover': { borderColor: '#00D4FF', backgroundColor: 'rgba(0,212,255,0.08)' },
              }}
            >
              {analysing ? 'Analysing…' : 'Run detection'}
            </Button>
            {summary?.session?.capture_start && (
              <Typography sx={{ fontSize: 12, color: 'rgba(229,231,235,0.55)' }}>
                traffic captured {new Date(summary.session.capture_start).toLocaleString()}
                {' · span '}
                {/* A missing span is not a span of zero — the same distinction
                    formatBytes and formatCount make in services/forensics.js. */}
                {summary.session.capture_duration_seconds == null
                  ? '—'
                  : `${Math.round(summary.session.capture_duration_seconds / 60)} min`}
              </Typography>
            )}
          </Box>

          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 10 }}>
              <CircularProgress sx={{ color: '#00D4FF' }} />
            </Box>
          ) : !sessions.length ? (
            <Box sx={{ ...PANEL, textAlign: 'center', py: 6 }}>
              <Typography sx={{ color: 'rgba(229,231,235,0.7)', mb: 1 }}>
                No capture sessions yet.
              </Typography>
              <Typography sx={{ fontSize: 13, color: 'rgba(229,231,235,0.55)' }}>
                Import one:&nbsp;
                <code>python manage.py import_pcap &lt;file.pcap&gt;</code>
              </Typography>
            </Box>
          ) : (
            <Box sx={{ display: 'flex', gap: 2.5, alignItems: 'flex-start', flexWrap: 'wrap' }}>
              <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                {/* Five real measures. Nothing here is a placeholder, and there
                    is deliberately no "Blocked" card — this is a passive
                    forensic tool and it cannot block anything. */}
                <Box sx={{ display: 'flex', gap: 1.5, mb: 2.5, flexWrap: 'wrap' }}>
                  <StatCard title="Packets" primary={formatCount(totals?.packets)}
                    secondary={formatBytes(totals?.bytes)} color="#00D4FF" />
                  <StatCard title="Flows" primary={formatCount(totals?.flows)}
                    secondary="conversations" color="#00E68A" />
                  <StatCard title="DNS queries" primary={formatCount(totals?.dns_queries)}
                    secondary="names queried" color="#A855F7" />
                  {/* No `?? 0` on the pending count: formatCount already
                      returns an em dash for a missing value, and coercing it to
                      zero would print "0 awaiting triage" — a measured claim —
                      when the figure simply did not arrive. */}
                  <StatCard title="Findings" primary={formatCount(totals?.detections)}
                    secondary={`${formatCount(totals?.detections_pending)} awaiting triage`}
                    color="#FFB020" />
                  <StatCard title="Flagged flows" primary={formatCount(totals?.flagged_flows)}
                    secondary="risk score > 0" color="#FF3B5C" />
                </Box>

                <Box sx={{ ...PANEL, mb: 2.5 }}>
                  <Typography sx={{ fontSize: 13, color: 'rgba(229,231,235,0.6)', mb: 0.5 }}>
                    Activity across the capture window
                  </Typography>
                  <Typography sx={{ fontSize: 11.5, color: 'rgba(229,231,235,0.55)', mb: 1.5 }}>
                    Bucketed from packet timestamps, not from processing time
                    {/* A week-long capture drawn in 30 points is one point per
                        5.6 hours, which can hide a burst completely. Saying
                        what each point covers is the difference between a
                        chart and a shape. */}
                    {bucketSeconds != null && ` · one point per ${
                      bucketSeconds >= 3600
                        ? `${(bucketSeconds / 3600).toFixed(1)} h`
                        : bucketSeconds >= 60
                          ? `${(bucketSeconds / 60).toFixed(1)} min`
                          : `${bucketSeconds.toFixed(0)} s`
                    }`}
                  </Typography>
                  <ResponsiveContainer width="100%" height={240}>
                    <AreaChart data={timeline} margin={{ top: 6, right: 6, left: -18, bottom: 0 }}>
                      <defs>
                        {[['gF', '#00D4FF'], ['gR', '#FF3B5C']].map(([id, c]) => (
                          <linearGradient key={id} id={id} x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={c} stopOpacity={0.28} />
                            <stop offset="100%" stopColor={c} stopOpacity={0} />
                          </linearGradient>
                        ))}
                      </defs>
                      <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
                      <XAxis dataKey="t" tick={{ fill: 'rgba(229,231,235,0.35)', fontSize: 10.5 }}
                        axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: 'rgba(229,231,235,0.35)', fontSize: 10.5 }}
                        axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{
                        backgroundColor: 'rgba(11,15,26,0.95)',
                        border: '1px solid rgba(0,212,255,0.25)',
                        borderRadius: 8, fontSize: 12,
                      }} />
                      <Area type="monotone" dataKey="flows" name="flows" stroke="#00D4FF"
                        strokeWidth={2} fill="url(#gF)" />
                      <Area type="monotone" dataKey="flagged" name="flagged" stroke="#FF3B5C"
                        strokeWidth={2} fill="url(#gR)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </Box>

                <SeverityBreakdown data={severities} />
              </Box>

              <Box sx={{
                // Fixed at 300px this column could not wrap, so on a phone
                // it pushed the page 250px wider than the screen.
                width: { xs: '100%', md: 300 },
                flexShrink: { xs: 1, md: 0 }, minWidth: 0,
                display: 'flex', flexDirection: 'column', gap: 2.5,
              }}>
                <ProtocolBubbles protocols={summary?.protocols ?? []} />
                <ProtocolRanking applications={summary?.applications ?? []} />
              </Box>
            </Box>
          )}
        </Box>
      </Box>
    </Box>
  );
}

export default DashboardPage;
