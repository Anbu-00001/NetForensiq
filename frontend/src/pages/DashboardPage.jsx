import { useEffect, useState } from 'react';
import { Box, Typography, MenuItem, Select, CircularProgress, Button, Alert } from '@mui/material';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import { describeError } from '../services/api';
import { useCurrentUser, canActOnEvidence } from '../services/session';
import Sidebar from '../components/layout/Sidebar';
import ClassificationBanner, { BANNER_HEIGHT } from '../components/layout/ClassificationBanner';
import TopBar from '../components/layout/TopBar';
import StatCard from '../components/dashboard/StatCard';
import NetworkGraph from '../components/graph/NetworkGraph';
import AttackScenario from '../components/scenario/AttackScenario';
import ProtocolBubbles from '../components/dashboard/ProtocolBubbles';
import ProtocolRanking from '../components/dashboard/ProtocolRanking';
import SeverityBreakdown from '../components/dashboard/SeverityBreakdown';
import {
  listSessions, getSessionSummary, getSessionTimeline, getSessionGraph,
  getSessionScenario,
  analyseSession,
  unwrap, formatBytes, formatCount,
} from '../services/forensics';

// Worst first, so a truncated list keeps what matters.
const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'];

// How often the dashboard re-reads a capture that is still running. Slow
// enough that it is not hammering an evidence machine, fast enough that an
// operator watching the screen sees a finding arrive rather than discovers
// it on a reload.
const LIVE_REFRESH_MS = 10_000;

const PANEL = {
  p: 2.5,
  borderRadius: 2,
  backgroundColor: '#F4F5F7',
  border: '1px solid #E2E5E9',
};

function DashboardPage() {
  const [sessions, setSessions] = useState([]);
  const [sessionId, setSessionId] = useState('');
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [graph, setGraph] = useState(null);
  // Who the diagram draws. Kept here rather than inside the graph so a
  // re-fetch is a normal data load and not a component reaching for the API.
  const [graphFocus, setGraphFocus] = useState('flagged');
  const [scenario, setScenario] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);

  // A capture that is still being taken. The dashboard refreshes itself while
  // one is running — the difference between a report on a file and a console
  // watching a wire — and stops the moment the capture does, so a finished
  // session is not polled forever. Declared here rather than beside the other
  // derived values because the polling effect below closes over it.
  const liveSession = summary?.session;
  const isLive = liveSession?.source_type === 'live'
    && liveSession?.state === 'running';
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
    Promise.all([
      getSessionSummary(sessionId),
      getSessionTimeline(sessionId),
      // The diagram is fetched alongside rather than after, so the page does
      // not render its most useful panel last.
      getSessionGraph(sessionId, { focus: graphFocus }).catch(() => null),
      // Two findings, not one. A single finding against a machine is a
      // finding; it is not a sequence, and listing it as one would inflate
      // the panel with hosts that have no story to tell.
      getSessionScenario(sessionId, { minFindings: 2 }).catch(() => null),
    ])
      .then(([s, t, g, sc]) => {
        if (!current) return;
        setSummary(s);
        setTimeline(t.series ?? []);
        setBucketSeconds(t.bucket_seconds ?? null);
        setGraph(g);
        setScenario(sc);
        setError('');
      })
      .catch((err) => { if (current) setError(describeError(err, 'Failed to load session data.')); })
      .finally(() => { if (current) setLoading(false); });

    // Switching sessions while a request is in flight would otherwise let the
    // slower response overwrite the newer one.
    return () => { current = false; };
  }, [sessionId, graphFocus, refreshKey]);

  // Poll only while a live capture is running. `refreshKey` re-enters the
  // effect above rather than duplicating its fetching here, so the two paths
  // cannot drift.
  useEffect(() => {
    if (!isLive) return undefined;
    const timer = setInterval(() => setRefreshKey((n) => n + 1), LIVE_REFRESH_MS);
    return () => clearInterval(timer);
  }, [isLive]);

  const runAnalysis = async () => {
    setAnalysing(true);
    try {
      await analyseSession(sessionId);
      const [s, t, g, sc] = await Promise.all([
        getSessionSummary(sessionId), getSessionTimeline(sessionId),
        getSessionGraph(sessionId, { focus: graphFocus }).catch(() => null),
        getSessionScenario(sessionId, { minFindings: 2 }).catch(() => null),
      ]);
      setSummary(s);
      setTimeline(t.series ?? []);
      setGraph(g);
      setScenario(sc);
    } catch {
      setError('Analysis failed.');
    } finally {
      setAnalysing(false);
    }
  };

  // A read-only account cannot run detection — the API refuses it. Offering
  // the button anyway produces a control that always fails, which is worse
  // than not offering it: the officer learns the tool is broken rather than
  // that the action is not theirs. This was the only page with no role check.
  const canAnalyse = canActOnEvidence(useCurrentUser());

  const totals = summary?.totals;
  const severities = summary?.detections_by_severity ?? [];


  // Derived from the timeline and summary that are already on screen — no
  // extra request, and nothing here is synthesised.
  const SEVERITY_HUE = {
    critical: '#B3261E', high: '#A84D08', medium: '#8A6100', low: '#1F3A5F',
  };
  const bucketLabel = (i) => `bucket ${i + 1}`;
  const bytesSeries = timeline.map((b, i) => ({ label: bucketLabel(i), value: b.bytes ?? 0 }));
  const flowSeries = timeline.map((b, i) => ({ label: bucketLabel(i), value: b.flows ?? 0 }));
  const flaggedSeries = timeline.map((b, i) => ({ label: bucketLabel(i), value: b.flagged ?? 0 }));
  const dnsSeries = (summary?.dns_top ?? []).map((d) => ({
    label: d.query_name, value: d.count,
  }));
  const severitySeries = [...severities]
    .sort((a, b) => (SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity)))
    .map((s) => ({ label: s.severity, value: s.count, colour: SEVERITY_HUE[s.severity] }));

  // A count of flagged flows means little without the denominator: twenty-two
  // out of eight hundred is a different screen from twenty-two out of thirty.
  const flaggedShare = (totals?.flagged_flows != null && totals?.flows)
    ? `${((totals.flagged_flows / totals.flows) * 100).toFixed(1)}% of all conversations`
    : null;

  return (
    <Box sx={{ display: 'flex', backgroundColor: '#FFFFFF', minHeight: '100vh',
      pt: `${BANNER_HEIGHT}px` }}>
      <ClassificationBanner level="restricted" fixed />
      <Sidebar />
      <Box sx={{ flexGrow: 1, minWidth: 0 }}>
        <TopBar />

        <Box sx={{ p: 2.5 }}>
          {/* Session selector — the dashboard always describes one capture */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2.5, flexWrap: 'wrap' }}>
            <Typography sx={{ fontSize: 13, color: '#5A6068' }}>
              Capture session
            </Typography>
            <Select
              size="small"
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              sx={{
                minWidth: { xs: 0, sm: 280 }, maxWidth: '100%',
                color: '#111315', fontSize: 13,
                backgroundColor: '#F4F5F7',
                '& .MuiOutlinedInput-notchedOutline': { borderColor: '#C7CCD2' },
                '& .MuiSvgIcon-root': { color: '#5A6068' },
              }}
            >
              {sessions.map((s) => (
                <MenuItem key={s.id} value={s.id}>
                  #{s.id} · {s.name} · {formatCount(s.packet_count)} pkts
                </MenuItem>
              ))}
            </Select>
            {canAnalyse ? (
              <Button
                size="small" variant="outlined" onClick={runAnalysis}
                disabled={!sessionId || analysing}
                sx={{
                  borderColor: 'rgba(7,110,124,0.45)', color: '#076E7C', fontSize: 12,
                  '&:hover': { borderColor: '#076E7C', backgroundColor: 'rgba(7,110,124,0.10)' },
                }}
              >
                {analysing ? 'Analysing…' : 'Run detection'}
              </Button>
            ) : (
              <Typography sx={{ fontSize: 12, color: '#5A6068' }}>
                Read-only access — detection is run by an investigating officer
              </Typography>
            )}
            {summary?.session?.capture_start && (
              <Typography sx={{ fontSize: 12, color: '#5A6068' }}>
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
              <CircularProgress sx={{ color: '#076E7C' }} />
            </Box>
          ) : !sessions.length ? (
            <Box sx={{ ...PANEL, textAlign: 'center', py: 6 }}>
              <Typography sx={{ color: '#2B3138', mb: 1 }}>
                No capture sessions yet.
              </Typography>
              <Typography sx={{ fontSize: 13, color: '#5A6068' }}>
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
                  {/*
                    Every card carries the distribution behind its figure, and
                    every series below is measured. Where the data for one is
                    not present the card renders the number alone rather than a
                    line that looks like history the capture does not contain.
                  */}
                  <StatCard title="Packets" primary={formatCount(totals?.packets)}
                    secondary={formatBytes(totals?.bytes)} color="#1F3A5F"
                    chart={{ kind: 'spark', series: bytesSeries }}
                    caption={bytesSeries.length ? 'Bytes across the capture window' : null} />

                  <StatCard title="Flows" primary={formatCount(totals?.flows)}
                    secondary="conversations" color="#1B6E3C"
                    chart={{ kind: 'spark', series: flowSeries }}
                    caption={flowSeries.length ? 'Conversations opened over time' : null} />

                  <StatCard title="DNS queries" primary={formatCount(totals?.dns_queries)}
                    secondary="names queried" color="#6B4FA8"
                    chart={{ kind: 'bars', series: dnsSeries }}
                    caption={dnsSeries.length ? 'Most-queried names' : null} />

                  {/* No `?? 0` on the pending count: formatCount already
                      returns an em dash for a missing value, and coercing it to
                      zero would print "0 awaiting triage" — a measured claim —
                      when the truth is that the figure never arrived. */}
                  <StatCard title="Findings" primary={formatCount(totals?.detections)}
                    secondary={`${formatCount(totals?.detections_pending)} awaiting triage`}
                    color="#8A6100"
                    chart={{ kind: 'bars', series: severitySeries }}
                    caption={severitySeries.length ? 'By severity' : null} />

                  <StatCard title="Flagged flows" primary={formatCount(totals?.flagged_flows)}
                    secondary="risk score > 0" color="#B3261E"
                    chart={{ kind: 'spark', series: flaggedSeries }}
                    caption={flaggedShare} />
                </Box>

                {/* The diagram sits above the counters deliberately. An
                    officer's first question is "which machine is in trouble",
                    which is a shape; "how many packets" is a detail that
                    follows. */}
                <Box sx={{ ...PANEL, mb: 2.5 }}>
                  <Typography sx={{ fontSize: 13, color: '#2B3138', mb: 0.3, fontWeight: 600 }}>
                    Who talked to whom
                  </Typography>
                  <Typography sx={{ fontSize: 11.5, color: '#5A6068', mb: 1 }}>
                    Each circle is a machine. Lines are conversations between
                    them; red lines carry something a rule flagged.
                  </Typography>
                  <NetworkGraph
                    data={graph}
                    focus={graphFocus}
                    onFocusChange={setGraphFocus}
                  />
                </Box>

                {/* The diagram says who talked to whom; this says in what
                    order. Directly beneath it because that is the order the
                    two questions arrive in. */}
                {scenario && (
                  <Box sx={{ ...PANEL, mb: 2.5 }}>
                    <Typography sx={{ fontSize: 13, color: '#2B3138', mb: 0.3, fontWeight: 600 }}>
                      What happened, in order
                    </Typography>
                    <Typography sx={{ fontSize: 11.5, color: '#5A6068', mb: 1.5 }}>
                      Findings against one machine, placed on the MITRE ATT&amp;CK
                      kill chain. A sequence of observations — not a proof that
                      one step caused the next.
                    </Typography>
                    <AttackScenario data={scenario} />
                  </Box>
                )}

                <Box sx={{ ...PANEL, mb: 2.5 }}>
                  <Typography sx={{ fontSize: 13, color: '#5A6068', mb: 0.5 }}>
                    Activity across the capture window
                  </Typography>
                  <Typography sx={{ fontSize: 11.5, color: '#5A6068', mb: 1.5 }}>
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
                        {[['gF', '#1F3A5F'], ['gR', '#B3261E']].map(([id, c]) => (
                          <linearGradient key={id} id={id} x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={c} stopOpacity={0.28} />
                            <stop offset="100%" stopColor={c} stopOpacity={0} />
                          </linearGradient>
                        ))}
                      </defs>
                      <CartesianGrid stroke="#F4F5F7" vertical={false} />
                      <XAxis dataKey="t" tick={{ fill: '#5F656D', fontSize: 10.5 }}
                        axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: '#5F656D', fontSize: 10.5 }}
                        axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{
                        backgroundColor: '#FFFFFF',
                        border: '1px solid #E2E5E9',
                        borderRadius: 8, fontSize: 12,
                      }} />
                      <Area type="monotone" dataKey="flows" name="flows" stroke="#1F3A5F"
                        strokeWidth={2} fill="url(#gF)" />
                      <Area type="monotone" dataKey="flagged" name="flagged" stroke="#B3261E"
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
