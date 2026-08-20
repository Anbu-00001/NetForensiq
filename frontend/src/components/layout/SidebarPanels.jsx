import { Box, Typography, Tooltip } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { usePosture } from '../../services/posture';
import { formatBytes } from '../../services/forensics';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, RULE, RULE_STRONG, PANEL, PAPER,
  CRITICAL, HIGH, MEDIUM, LOW, INTACT, MONO,
} from '../../theme/tokens';

/**
 * The rest of the operator strip: what is owed, what is being recorded, and
 * what is about to run out.
 *
 * The selection rule
 * ------------------
 * Permanent screen space is the most expensive space in an application,
 * because whatever occupies it is seen a thousand times and read twice. Two
 * kinds of fact earn it:
 *
 *   **An obligation with a date on it.** A statutory duty an officer can miss
 *   by simply not looking — and not looking is exactly what happens on a busy
 *   week.
 *
 *   **A state that fails silently.** A stopped capture, a disk about to fill,
 *   a certificate stranded half-signed. Each of these looks identical to
 *   working right up until somebody needs it.
 *
 * Anything merely interesting belongs on a page. The research behind each
 * choice, with the statutory citation and its verification, is in
 * research/140_SIDEBAR_FEATURE_RESEARCH.md; the server side is
 * backend/evidence/posture.py.
 */

const SEVERITY_INK = {
  critical: CRITICAL, high: HIGH, medium: MEDIUM, low: LOW,
};

function PanelShell({ title, children, sx = {} }) {
  return (
    <Box sx={{
      p: 1.4, borderRadius: 1, backgroundColor: PANEL,
      border: `1px solid ${RULE}`, mb: 1.5, ...sx,
    }}>
      <Typography sx={{
        fontSize: 9.5, letterSpacing: 1, color: INK_SOFT, fontWeight: 700, mb: 1.1,
      }}>
        {title}
      </Typography>
      {children}
    </Box>
  );
}

/**
 * One line of an obligation: a count, what it is, and what to do about it.
 *
 * Clickable where there is somewhere to go. A number an officer cannot act on
 * from where they are reading it is a number they learn to scroll past.
 */
function Duty({ count, label, detail, tone = GREY_MUTED, onClick }) {
  return (
    <Box
      onClick={onClick}
      sx={{
        display: 'flex', gap: 1, alignItems: 'baseline', mb: 1,
        cursor: onClick ? 'pointer' : 'default',
        '&:hover': onClick ? { '& .nf-duty-label': { color: INK } } : {},
      }}
    >
      <Typography sx={{
        fontSize: 15, fontWeight: 700, fontFamily: MONO, color: tone,
        lineHeight: 1.1, minWidth: 26,
      }}>
        {count}
      </Typography>
      <Box sx={{ minWidth: 0 }}>
        <Typography className="nf-duty-label" sx={{
          fontSize: 11, lineHeight: 1.3, color: INK_SOFT, fontWeight: 600,
        }}>
          {label}
        </Typography>
        {detail && (
          <Typography sx={{ fontSize: 9.5, lineHeight: 1.35, color: GREY, mt: 0.1 }}>
            {detail}
          </Typography>
        )}
      </Box>
    </Box>
  );
}

/**
 * What is owed right now.
 *
 * The panel states plainly when nothing is owed rather than disappearing: an
 * empty duty board and a duty board that failed to load must not look the
 * same, or the one week it silently stops working is the week it is trusted
 * most.
 */
export function DutyBoard() {
  const posture = usePosture();
  const navigate = useNavigate();
  if (!posture) return null;

  const { triage, certificates, docket } = posture;
  const waiting = triage?.awaiting_review ?? 0;
  const incomplete = certificates?.incomplete ?? 0;
  const overdue = docket?.updates_due ?? 0;

  if (!waiting && !incomplete && !overdue) {
    return (
      <PanelShell title="OUTSTANDING">
        <Typography sx={{ fontSize: 10.5, color: GREY, lineHeight: 1.4 }}>
          Nothing awaiting review, every certificate complete.
        </Typography>
      </PanelShell>
    );
  }

  const worst = triage?.worst_waiting;
  const split = triage?.by_severity ?? {};
  const severityLine = ['critical', 'high', 'medium', 'low']
    .filter((level) => split[level])
    .map((level) => `${split[level]} ${level}`)
    .join(' · ');

  return (
    <PanelShell title="OUTSTANDING">
      {waiting > 0 && (
        <Duty
          count={waiting}
          label="findings awaiting review"
          detail={severityLine}
          tone={SEVERITY_INK[worst] ?? GREY_MUTED}
          onClick={() => navigate('/detections')}
        />
      )}

      {incomplete > 0 && (
        <Duty
          count={incomplete}
          label={incomplete === 1 ? 'certificate incomplete' : 'certificates incomplete'}
          // s.63(4) needs both signatures conjunctively, so which half is
          // missing decides who has to be found — an expert, or the person who
          // held the device.
          detail={[
            certificates.awaiting_part_b && `${certificates.awaiting_part_b} awaiting Part B (expert)`,
            certificates.awaiting_part_a && `${certificates.awaiting_part_a} awaiting Part A`,
            certificates.unsigned && `${certificates.unsigned} unsigned`,
          ].filter(Boolean).join(' · ')}
          tone={CRITICAL}
          onClick={() => navigate('/evidence')}
        />
      )}

      {overdue > 0 && (
        <Duty
          count={overdue}
          label={overdue === 1 ? 'case past 90 days' : 'cases past 90 days'}
          detail="Informant/victim update — BNSS s.193(3)(ii)"
          tone={CRITICAL}
        />
      )}
    </PanelShell>
  );
}

/**
 * The ninety-day bar for one case.
 *
 * BNSS 2023 s.193(3)(ii): the investigating officer "shall, within a period of
 * ninety days, inform the progress of the investigation ... to the informant or
 * the victim." The duty is printed under every bar, every time, because the
 * number alone is ambiguous with two other deadlines an officer carries — the
 * s.187(3) default-bail clock, which runs from arrest and which this system
 * cannot compute at all, and the filing of the report itself. A bar labelled
 * only "Day 64 of 90" would eventually be read as one of those, and acted on.
 */
function InformantClock({ clock }) {
  if (!clock) return null;
  const pct = Math.max(0, Math.min(100, (clock.day / clock.of) * 100));
  const tone = clock.overdue ? CRITICAL : (pct >= 75 ? MEDIUM : INK_SOFT);
  const late = Math.abs(clock.days_left);

  return (
    <Box sx={{ mt: 0.5 }}>
      <Box sx={{
        height: 3, backgroundColor: RULE_STRONG, borderRadius: 2, overflow: 'hidden',
      }}>
        <Box sx={{ width: `${pct}%`, height: '100%', backgroundColor: tone }} />
      </Box>
      <Typography sx={{
        fontSize: 9.5, color: clock.overdue ? CRITICAL : GREY, mt: 0.35,
        fontWeight: clock.overdue ? 700 : 400, lineHeight: 1.3,
      }}>
        {clock.overdue
          ? `Update overdue by ${late} day${late === 1 ? '' : 's'}`
          : `Day ${clock.day} of ${clock.of}`}
      </Typography>
      <Typography sx={{ fontSize: 9, color: GREY_MUTED, lineHeight: 1.3 }}>
        {clock.duty} · {clock.authority}
      </Typography>
    </Box>
  );
}

/**
 * The cases this officer is on, and in what capacity.
 *
 * Capacity is printed rather than merely stored because BSA s.63(4) needs two
 * *different* people. An officer who can see they are the IO on a case knows
 * without asking that they cannot also sign Part B on it — and the server
 * already refuses, so the alternative is finding out at the moment of signing.
 */
export function CaseDocket() {
  const posture = usePosture();
  if (!posture) return null;

  const docket = posture.docket;
  if (!docket?.total) {
    return (
      <PanelShell title="MY DOCKET">
        <Typography sx={{ fontSize: 10.5, color: GREY, lineHeight: 1.4 }}>
          No case assigned to this account.
        </Typography>
      </PanelShell>
    );
  }

  return (
    <PanelShell title={`MY DOCKET · ${docket.total}`}>
      {docket.cases.map((row) => (
        <Box key={row.case_number} sx={{ mb: 1.3, '&:last-of-type': { mb: 0 } }}>
          <Box sx={{ display: 'flex', gap: 0.7, alignItems: 'center', mb: 0.15 }}>
            <Typography sx={{
              fontSize: 8.5, letterSpacing: 0.6, fontWeight: 700, color: PAPER,
              backgroundColor: INK_SOFT, px: 0.5, borderRadius: 0.4, flexShrink: 0,
            }}>
              {row.capacity.toUpperCase()}
            </Typography>
            <Tooltip title={row.title} placement="right">
              <Typography sx={{
                fontSize: 10.5, fontFamily: MONO, color: INK, minWidth: 0,
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}>
                {row.case_number}
              </Typography>
            </Tooltip>
          </Box>
          <Typography sx={{ fontSize: 9.5, color: GREY, lineHeight: 1.3 }}>
            {row.fir_number ? `FIR ${row.fir_number}` : row.status_label}
          </Typography>
          <InformantClock clock={row.informant_update} />
        </Box>
      ))}
    </PanelShell>
  );
}

/**
 * Whether anything is being recorded, and how much room is left to record it
 * into.
 *
 * These two sit together because they fail together. A capture that runs out
 * of disk does not stop cleanly: it leaves a file shorter than the traffic it
 * was recording, and nothing about that file announces the fact. Its hash will
 * verify — it is a hash of what was written. An exhibit that is intact and
 * incomplete is the worst failure this system has, because every check it
 * performs will pass.
 */
export function CaptureHealth() {
  const posture = usePosture();
  if (!posture) return null;

  const capture = posture.capture;
  const store = posture.store;

  const observed = capture?.observed_at ? new Date(capture.observed_at) : null;
  const asOf = observed
    ? `${String(observed.getHours()).padStart(2, '0')}:${String(observed.getMinutes()).padStart(2, '0')}`
    : null;

  const diskTone = { critical: CRITICAL, warning: MEDIUM, ok: GREY_MUTED }[store?.level]
    ?? GREY_MUTED;

  return (
    <PanelShell title="CAPTURE">
      {capture?.running ? (
        <Box sx={{ mb: 1.1 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mb: 0.3 }}>
            {/* The only animation in the sidebar, and it carries a fact: it
                stops when the capture does. */}
            <Box sx={{
              width: 7, height: 7, borderRadius: '50%', backgroundColor: INTACT,
              flexShrink: 0,
              animation: 'nfPulse 1.8s ease-in-out infinite',
              '@keyframes nfPulse': {
                '0%, 100%': { opacity: 1 },
                '50%': { opacity: 0.25 },
              },
              '@media (prefers-reduced-motion: reduce)': { animation: 'none' },
            }} />
            <Typography sx={{ fontSize: 11, fontWeight: 700, color: INK_SOFT }}>
              Recording
            </Typography>
          </Box>
          <Typography sx={{ fontSize: 10, fontFamily: MONO, color: INK, lineHeight: 1.4 }}>
            {capture.session.packet_count.toLocaleString()} packets ·{' '}
            {capture.session.flow_count.toLocaleString()} flows
          </Typography>
          {/* Without this the reader cannot tell a live figure from one that
              stopped advancing four minutes ago. */}
          <Typography sx={{ fontSize: 9.5, color: GREY_MUTED, lineHeight: 1.3 }}>
            {capture.session.interface || capture.session.source_type}
            {asOf ? ` · counted at ${asOf}` : ''}
          </Typography>
        </Box>
      ) : (
        <Box sx={{ mb: 1.1 }}>
          <Typography sx={{ fontSize: 11, color: INK_SOFT, fontWeight: 600 }}>
            Not recording
          </Typography>
          <Typography sx={{ fontSize: 9.5, color: GREY, lineHeight: 1.35 }}>
            {capture?.last_session
              ? `Last: ${capture.last_session.name} — ${capture.last_session.state_label.toLowerCase()}`
              : 'No capture has been run on this installation'}
          </Typography>
        </Box>
      )}

      {store?.available && (
        <Box>
          <Typography sx={{
            fontSize: 9.5, letterSpacing: 0.9, color: GREY_MUTED, mb: 0.3,
          }}>
            EVIDENCE VOLUME
          </Typography>
          <Box sx={{
            height: 3, backgroundColor: RULE_STRONG, borderRadius: 2, overflow: 'hidden',
          }}>
            <Box sx={{
              width: `${100 - store.free_pct}%`, height: '100%',
              backgroundColor: store.level === 'ok' ? INK_SOFT : diskTone,
            }} />
          </Box>
          <Typography sx={{
            fontSize: 9.5, color: store.level === 'ok' ? GREY : diskTone,
            fontWeight: store.level === 'ok' ? 400 : 700, mt: 0.35, lineHeight: 1.3,
          }}>
            {formatBytes(store.free_bytes)} free · {store.free_pct}%
          </Typography>
          {store.level !== 'ok' && (
            <Typography sx={{ fontSize: 9, color: diskTone, lineHeight: 1.3 }}>
              A capture that fills the disk leaves a short file that still hashes.
            </Typography>
          )}
        </Box>
      )}

      {store && !store.available && (
        <Typography sx={{ fontSize: 9.5, color: CRITICAL, lineHeight: 1.35 }}>
          Evidence volume unreadable — check that it is mounted.
        </Typography>
      )}
    </PanelShell>
  );
}

/**
 * Which indicator feeds this machine holds, and how old they are.
 *
 * A feed going stale is invisible without this. Detection keeps running,
 * findings keep appearing, and nothing distinguishes "the lists we hold say
 * this traffic is clean" from "the lists we hold are a year old and would not
 * know". The number that matters is therefore the age, not the entry count.
 *
 * The empty state is stated plainly rather than warned about. A workstation
 * nobody has carried a feed to is correctly configured — none of this tool's
 * own rules depend on one — and an amber badge there would train an officer to
 * ignore the badge that matters.
 */
export function IntelFeeds() {
  const posture = usePosture();
  if (!posture) return null;

  const feeds = posture.feeds;
  if (!feeds) return null;

  if (!feeds.loaded) {
    return (
      <PanelShell title="INDICATOR FEEDS">
        <Typography sx={{ fontSize: 10.5, color: GREY, lineHeight: 1.45 }}>
          {feeds.note}
        </Typography>
      </PanelShell>
    );
  }

  const tone = { stale: CRITICAL, ageing: MEDIUM, current: INTACT }[feeds.level]
    ?? GREY_MUTED;

  return (
    <PanelShell title={`INDICATOR FEEDS · ${feeds.loaded}`}>
      {feeds.feeds.map((feed) => (
        <Box key={feed.name} sx={{ mb: 0.9, '&:last-of-type': { mb: 0 } }}>
          <Typography sx={{
            fontSize: 10.5, color: INK_SOFT, fontWeight: 600, lineHeight: 1.3,
          }}>
            {feed.name}
          </Typography>
          <Typography sx={{ fontSize: 9.5, fontFamily: MONO, color: GREY }}>
            {feed.entry_count.toLocaleString()} indicators
          </Typography>
          <Typography sx={{
            fontSize: 9.5, lineHeight: 1.35,
            color: feeds.level === 'current' ? GREY : tone,
            fontWeight: feeds.level === 'current' ? 400 : 700,
          }}>
            obtained {feed.age_days === 0 ? 'today' : `${feed.age_days} day${
              feed.age_days === 1 ? '' : 's'} ago`}
          </Typography>
        </Box>
      ))}
      {feeds.level === 'stale' && (
        <Typography sx={{ fontSize: 9, color: CRITICAL, lineHeight: 1.35, mt: 0.5 }}>
          Older than 90 days. Addresses get reassigned; a match this far from
          the traffic needs confirming.
        </Typography>
      )}
    </PanelShell>
  );
}

export default DutyBoard;
