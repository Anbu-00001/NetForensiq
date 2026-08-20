import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Box, Typography, Button, MenuItem, TextField, Slider, Alert, Tooltip,
} from '@mui/material';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, RULE, RULE_STRONG, PANEL, PANEL_ALT, PAPER,
  CRITICAL, INTACT, CYAN, CYAN_FILL, CYAN_WASH, MONO,
} from '../../theme/tokens';
import {
  getMonitorStatus, listInterfaces, startMonitor, stopMonitor,
} from '../../services/forensics';

/**
 * Watching an interface, drawn rather than tabulated.
 *
 * Why a picture
 * -------------
 * "Real-time alerting" is the claim most easily made and least easily
 * believed. A counter that says `alerts_delivered: 3` proves nothing to
 * somebody who has just been told a number; what convinces them is seeing
 * where a packet goes after it arrives, and watching the count move along that
 * path. So the panel is the pipeline itself — interface, packets, window,
 * findings, sinks — with the live figure sitting on the stage it belongs to.
 *
 * The stage that matters is the last one. A finding that was raised and not
 * delivered is the failure this whole feature exists to avoid, and it is drawn
 * as its own box with its own count rather than folded into a total, because
 * "3 alerts" covering two successes and a refused connection is the sentence
 * that stops an operator watching the console.
 *
 * Restraint
 * ---------
 * One thing animates, and only while a capture is running: the dot travelling
 * the pipeline. It stops when the capture stops, so the motion carries a fact
 * rather than decorating one. Everything else is static, and every colour
 * answers a question — green delivered, red raised or refused, grey structure.
 * Under `prefers-reduced-motion` nothing moves at all.
 */

const POLL_MS = 4000;

function Stage({ label, value, hint, tone = INK, lit, wide }) {
  return (
    <Box sx={{
      flex: wide ? '1.4 1 150px' : '1 1 118px', minWidth: 0,
      px: 1.3, py: 1.1, borderRadius: 1,
      border: `1px solid ${lit ? RULE_STRONG : RULE}`,
      backgroundColor: lit ? PAPER : PANEL_ALT,
      borderTop: `3px solid ${lit ? tone : RULE_STRONG}`,
    }}>
      <Typography sx={{
        fontSize: 9, letterSpacing: 0.9, color: GREY_MUTED, fontWeight: 700,
      }}>
        {label.toUpperCase()}
      </Typography>
      <Typography sx={{
        fontSize: 19, fontFamily: MONO, fontWeight: 700, lineHeight: 1.2,
        color: lit ? INK : GREY_MUTED,
      }}>
        {value}
      </Typography>
      <Typography sx={{ fontSize: 10, color: GREY, lineHeight: 1.35 }}>
        {hint}
      </Typography>
    </Box>
  );
}

/** A chevron between two stages, so the panel reads left to right as a flow. */
function Arrow({ lit }) {
  return (
    <Box sx={{
      display: { xs: 'none', sm: 'flex' }, alignItems: 'center',
      px: 0.4, flexShrink: 0,
    }}>
      <svg width="13" height="13" viewBox="0 0 13 13" aria-hidden="true">
        <path d="M2,2 L8,6.5 L2,11" fill="none"
          stroke={lit ? INK_SOFT : RULE_STRONG} strokeWidth="1.6"
          strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </Box>
  );
}

/**
 * The last twenty windows as a strip.
 *
 * Height is packets seen in that window; a red tick above a bar means a
 * finding was raised in it. Two facts in one glance: is traffic arriving, and
 * did anything come of it.
 */
function ActivityStrip({ windows, windowSeconds }) {
  if (!windows.length) {
    return (
      <Typography sx={{ fontSize: 11, color: GREY, py: 1.5 }}>
        No window has closed yet. The first figures appear after{' '}
        {windowSeconds} seconds.
      </Typography>
    );
  }

  const peak = Math.max(1, ...windows.map((w) => w.packets));
  const width = 100 / windows.length;

  return (
    <Box>
      <Box sx={{
        display: 'flex', alignItems: 'flex-end', gap: '2px', height: 46,
        borderBottom: `1px solid ${RULE_STRONG}`, mb: 0.4,
      }}>
        {windows.map((w) => {
          const share = Math.max(0.04, w.packets / peak);
          return (
            <Tooltip
              key={w.window} placement="top"
              title={`Window ${w.window}: ${w.packets.toLocaleString()} packets, `
                   + `${w.flows.toLocaleString()} conversations`
                   + (w.findings_new ? `, ${w.findings_new} new finding(s)` : '')}
            >
              <Box sx={{
                width: `${width}%`, minWidth: 3, position: 'relative',
                height: '100%', display: 'flex', alignItems: 'flex-end',
              }}>
                {w.findings_new > 0 && (
                  <Box sx={{
                    position: 'absolute', top: 0, left: 0, right: 0, height: 3,
                    backgroundColor: CRITICAL, borderRadius: 1,
                  }} />
                )}
                <Box sx={{
                  width: '100%', height: `${share * 100}%`,
                  backgroundColor: w.findings_new ? CRITICAL : CYAN_FILL,
                  opacity: w.findings_new ? 0.9 : 0.55,
                  borderRadius: '2px 2px 0 0',
                }} />
              </Box>
            </Tooltip>
          );
        })}
      </Box>
      <Typography sx={{ fontSize: 10, color: GREY_MUTED, lineHeight: 1.4 }}>
        One bar per {windowSeconds}s window, newest on the right. Height is
        packets seen; a red cap means a finding was raised in that window.
      </Typography>
    </Box>
  );
}

/** Where an alert goes, named before one is raised. */
function Sinks({ sinks }) {
  if (!sinks) return null;
  if (!sinks.configured) {
    return (
      <Box sx={{
        p: 1.2, borderRadius: 1, border: `1px dashed ${RULE_STRONG}`,
        backgroundColor: PANEL_ALT,
      }}>
        <Typography sx={{ fontSize: 11, color: INK_SOFT, fontWeight: 600 }}>
          No alert sink configured
        </Typography>
        <Typography sx={{ fontSize: 10.5, color: GREY, lineHeight: 1.45 }}>
          {sinks.note}
        </Typography>
      </Box>
    );
  }
  return (
    <Box sx={{ display: 'flex', gap: 0.8, flexWrap: 'wrap' }}>
      {sinks.sinks.map((sink) => (
        <Box key={`${sink.kind}-${sink.target}`} sx={{
          px: 1.1, py: 0.7, borderRadius: 1,
          border: `1px solid ${RULE}`, backgroundColor: CYAN_WASH,
        }}>
          <Typography sx={{
            fontSize: 9.5, letterSpacing: 0.7, fontWeight: 700, color: CYAN,
          }}>
            {sink.kind.toUpperCase()} · {sink.transport.toUpperCase()}
          </Typography>
          <Typography sx={{ fontSize: 11, fontFamily: MONO, color: INK_SOFT }}>
            {sink.target}
          </Typography>
        </Box>
      ))}
    </Box>
  );
}

function LiveWatch() {
  const [state, setState] = useState(null);
  const [ifaces, setIfaces] = useState(null);
  const [chosen, setChosen] = useState('');
  const [window_, setWindow] = useState(30);
  const [homeNet, setHomeNet] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const timer = useRef(null);

  useEffect(() => {
    let live = true;
    listInterfaces()
      .then((data) => {
        if (!live) return;
        setIfaces(data);
        if (data.interfaces?.length && !chosen) {
          // Loopback first is almost never what an officer wants to watch.
          const real = data.interfaces.find((n) => n !== 'lo');
          setChosen(real ?? data.interfaces[0]);
        }
      })
      .catch(() => { if (live) setIfaces({ interfaces: [], can_capture: false }); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let live = true;
    const poll = () => getMonitorStatus()
      .then((data) => { if (live) setState(data); })
      .catch(() => {});
    poll();
    timer.current = setInterval(poll, POLL_MS);
    return () => { live = false; clearInterval(timer.current); };
  }, []);

  const running = !!state?.running;
  const windows = useMemo(() => state?.recent ?? [], [state]);

  const act = async (fn) => {
    setBusy(true);
    setError('');
    try {
      setState(await fn());
    } catch (err) {
      setError(err?.response?.data?.detail ?? 'The monitor did not respond.');
    } finally {
      setBusy(false);
    }
  };

  const undelivered = (state?.alerts_attempted ?? 0) - (state?.alerts_delivered ?? 0);

  return (
    <Box>
      <Typography sx={{ fontSize: 11.5, color: GREY, mb: 1.5, lineHeight: 1.6 }}>
        A network card on an air-gapped machine still sees traffic. This watches
        one, re-runs every rule at the end of each window, and pushes anything
        newly found to whatever sink is configured — so the delay between a
        packet arriving and an officer being told is one window, not the length
        of the capture.
      </Typography>

      {/* The pipeline. */}
      <Box sx={{ display: 'flex', alignItems: 'stretch', flexWrap: 'wrap', gap: 0.3, mb: 1.5 }}>
        <Stage
          label="Interface" lit={running} tone={INTACT} wide
          value={running ? state.interface : (chosen || '—')}
          hint={running ? 'in promiscuous mode' : 'not watching'}
        />
        <Arrow lit={running} />
        <Stage
          label="Packets seen" lit={running} tone={CYAN}
          value={(state?.packets ?? 0).toLocaleString()}
          hint={`${(state?.flows ?? 0).toLocaleString()} conversations`}
        />
        <Arrow lit={running} />
        <Stage
          label="Windows closed" lit={running} tone={CYAN}
          value={state?.windows ?? 0}
          hint={`every ${state?.window_seconds ?? window_}s, whole session re-run`}
        />
        <Arrow lit={running} />
        <Stage
          label="Findings raised" lit={running} tone={CRITICAL}
          value={state?.findings_new_total ?? 0}
          hint={`${state?.findings_total ?? 0} standing in this session`}
        />
        <Arrow lit={running} />
        <Stage
          label="Alerts out" lit={running} wide
          tone={undelivered > 0 ? CRITICAL : INTACT}
          value={`${state?.alerts_delivered ?? 0}/${state?.alerts_attempted ?? 0}`}
          hint={undelivered > 0
            ? `${undelivered} did not reach their sink`
            : 'delivered / attempted'}
        />
      </Box>

      {/* The one animation, and it carries a fact: it stops when capture does. */}
      {running && (
        <Box sx={{
          height: 2, borderRadius: 2, mb: 1.5, overflow: 'hidden',
          backgroundColor: PANEL_ALT, position: 'relative',
        }}>
          <Box sx={{
            position: 'absolute', top: 0, bottom: 0, width: '22%',
            background: `linear-gradient(90deg, transparent, ${CYAN_FILL}, transparent)`,
            animation: 'nfFlow 2.6s linear infinite',
            '@keyframes nfFlow': {
              from: { left: '-22%' },
              to: { left: '100%' },
            },
            '@media (prefers-reduced-motion: reduce)': { animation: 'none', left: 0 },
          }} />
        </Box>
      )}

      {error && <Alert severity="error" sx={{ mb: 1.5, fontSize: 12.5 }}>{error}</Alert>}

      {state?.error && (
        <Alert severity="error" sx={{ mb: 1.5, fontSize: 12.5 }}>
          The monitor stopped on an error: {state.error}
        </Alert>
      )}

      {ifaces && !ifaces.can_capture && !running && (
        <Alert severity="warning" sx={{ mb: 1.5, fontSize: 12.5 }}>
          {ifaces.reason || 'This process cannot capture packets.'} Without the
          capability, a capture starts, sees nothing, and reports no error —
          which is why it is refused up front rather than allowed to look alive.
        </Alert>
      )}

      <Box sx={{
        display: 'grid', gap: 2, mb: 1.5,
        gridTemplateColumns: { xs: '1fr', md: '1.3fr 1fr' },
      }}>
        <Box sx={{
          p: 1.4, borderRadius: 1, border: `1px solid ${RULE}`,
          backgroundColor: PAPER,
        }}>
          <Typography sx={{
            fontSize: 9.5, letterSpacing: 0.9, fontWeight: 700,
            color: INK_SOFT, mb: 0.8,
          }}>
            ACTIVITY
          </Typography>
          <ActivityStrip windows={windows} windowSeconds={state?.window_seconds ?? window_} />
          {state?.seconds_since_window != null && running && (
            <Typography sx={{
              fontSize: 10, mt: 0.5, lineHeight: 1.4,
              color: state.seconds_since_window > (state.window_seconds * 2.5)
                ? CRITICAL : GREY_MUTED,
              fontWeight: state.seconds_since_window > (state.window_seconds * 2.5)
                ? 700 : 400,
            }}>
              {state.seconds_since_window > (state.window_seconds * 2.5)
                ? `No window has closed for ${Math.round(state.seconds_since_window)}s — `
                  + 'longer than expected. The counts above may be stale.'
                : `Counts last confirmed ${Math.round(state.seconds_since_window)}s ago.`}
            </Typography>
          )}
        </Box>

        <Box sx={{
          p: 1.4, borderRadius: 1, border: `1px solid ${RULE}`,
          backgroundColor: PAPER,
        }}>
          <Typography sx={{
            fontSize: 9.5, letterSpacing: 0.9, fontWeight: 700,
            color: INK_SOFT, mb: 0.8,
          }}>
            WHERE ALERTS GO
          </Typography>
          <Sinks sinks={state?.sinks} />
          {!!state?.deliveries?.length && (
            <Box sx={{ mt: 1 }}>
              {state.deliveries.slice(0, 4).map((d, i) => (
                <Box key={`${d.sink}-${i}`} sx={{
                  display: 'flex', gap: 0.7, alignItems: 'baseline', mb: 0.3,
                }}>
                  <Box sx={{
                    width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                    backgroundColor: d.ok ? INTACT : CRITICAL,
                    // Shape as well as colour, for a reader who cannot rely on hue.
                    border: d.ok ? 'none' : `1px solid ${CRITICAL}`,
                  }} />
                  <Typography sx={{ fontSize: 10.5, color: INK_SOFT }}>
                    {d.sink}
                  </Typography>
                  <Typography sx={{ fontSize: 10, color: d.ok ? GREY : CRITICAL }}>
                    {d.detail}
                  </Typography>
                </Box>
              ))}
            </Box>
          )}
        </Box>
      </Box>

      {!!state?.newest_findings?.length && (
        <Box sx={{ mb: 1.5 }}>
          <Typography sx={{
            fontSize: 9.5, letterSpacing: 0.9, fontWeight: 700, color: INK_SOFT, mb: 0.5,
          }}>
            MOST RECENT
          </Typography>
          {state.newest_findings.slice(0, 5).map((f, i) => (
            <Box key={`${f.at}-${i}`} sx={{
              display: 'flex', gap: 1, py: 0.4,
              borderTop: `1px solid ${RULE}`,
            }}>
              <Box sx={{ width: 3, backgroundColor: CRITICAL, borderRadius: 2, flexShrink: 0 }} />
              <Typography sx={{ fontSize: 11.5, color: INK }}>{f.title}</Typography>
            </Box>
          ))}
        </Box>
      )}

      {/* Controls. */}
      <Box sx={{
        p: 1.6, borderRadius: 1, backgroundColor: PANEL,
        border: `1px solid ${RULE}`,
      }}>
        <Box sx={{
          display: 'grid', gap: 1.5, alignItems: 'end',
          gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr 1.6fr auto' },
        }}>
          <Box>
            <Typography sx={{ fontSize: 9.5, letterSpacing: 0.8, fontWeight: 700, color: INK_SOFT, mb: 0.4 }}>
              INTERFACE
            </Typography>
            <TextField
              select fullWidth size="small" value={chosen} disabled={running}
              onChange={(e) => setChosen(e.target.value)}
              sx={{ '& .MuiOutlinedInput-root': { backgroundColor: PAPER, fontSize: 12.5 } }}
            >
              {(ifaces?.interfaces ?? []).map((n) => (
                <MenuItem key={n} value={n} sx={{ fontSize: 12.5, fontFamily: MONO }}>
                  {n}
                </MenuItem>
              ))}
            </TextField>
          </Box>

          <Box>
            <Typography sx={{ fontSize: 9.5, letterSpacing: 0.8, fontWeight: 700, color: INK_SOFT, mb: 0.4 }}>
              MONITORED NETWORK
            </Typography>
            <TextField
              fullWidth size="small" value={homeNet} disabled={running}
              onChange={(e) => setHomeNet(e.target.value)}
              placeholder="10.0.0.0/8"
              sx={{ '& .MuiOutlinedInput-root': { backgroundColor: PAPER, fontSize: 12.5 } }}
            />
          </Box>

          <Box>
            <Typography sx={{ fontSize: 9.5, letterSpacing: 0.8, fontWeight: 700, color: INK_SOFT, mb: 0.4 }}>
              WINDOW — {running ? state.window_seconds : window_}s BETWEEN PASSES
            </Typography>
            <Slider
              size="small" min={5} max={300} step={5}
              value={running ? state.window_seconds : window_}
              disabled={running}
              onChange={(_e, v) => setWindow(v)}
              sx={{ color: CYAN, mt: 0.5 }}
            />
          </Box>

          <Button
            variant="contained" disabled={busy || (!running && !chosen)}
            onClick={() => act(running
              ? stopMonitor
              : () => startMonitor({
                interface: chosen, window_seconds: window_, home_net: homeNet,
              }))}
            sx={{
              textTransform: 'none', fontWeight: 600, fontSize: 13, px: 2.5,
              backgroundColor: running ? CRITICAL : INK,
              '&:hover': { backgroundColor: running ? CRITICAL : INK_SOFT },
            }}
          >
            {busy ? '…' : running ? 'Stop watching' : 'Start watching'}
          </Button>
        </Box>

        <Typography sx={{ fontSize: 10.5, color: GREY, mt: 1.2, lineHeight: 1.5 }}>
          Every rule runs over the <em>whole</em> session each pass, not over the
          window. A beacon calling home every 45 seconds is a claim about a time
          series — a 30-second slice of it is two packets and no periodicity. It
          costs more and it is the only thing that finds what these rules look
          for. Stopping takes effect at the end of the current window, so no
          window is left half-analysed.
        </Typography>
      </Box>
    </Box>
  );
}

export default LiveWatch;
