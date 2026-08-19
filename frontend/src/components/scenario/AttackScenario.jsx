import { useMemo, useState } from 'react';
import { Box, Typography, Collapse } from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, RULE, RULE_STRONG, PANEL, PANEL_ALT, PAPER,
  CRITICAL, HIGH, MEDIUM, LOW, CYAN, CYAN_WASH, MONO,
} from '../../theme/tokens';

/**
 * What was observed against one machine, in kill-chain order.
 *
 * The diagram beside this answers "who talked to whom". This answers the
 * question that follows it — "and in what order" — which is the one an officer
 * has to answer in a charge sheet.
 *
 * What this deliberately does not do
 * ----------------------------------
 * It does not write a narrative. Every automated attack-story feature is one
 * bad sentence away from asserting causation the evidence does not carry, and
 * a report that says "the attacker then exfiltrated the data" when what
 * happened is "a volume asymmetry crossed a threshold fifteen minutes later"
 * is the sentence a defence expert builds a cross-examination on.
 *
 * So the language throughout is *was seen at*, the stage track shows the four
 * tactics a packet capture can reach and the panel underneath names the ten it
 * cannot, and where the packet clock disagrees with the ordering the
 * disagreement is printed in red rather than sorted away. The server side and
 * the reasoning behind each of those is backend/capture/scenario.py.
 */

const SEVERITY_INK = {
  critical: CRITICAL, high: HIGH, medium: MEDIUM, low: LOW,
};

/** 2026-08-18T11:09:55+00:00 → 18 Aug 11:09:55 */
function clock(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const pad = (n) => String(n).padStart(2, '0');
  const month = d.toLocaleString('en-GB', { month: 'short' });
  return `${pad(d.getDate())} ${month} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/**
 * The four stages a tap can reach, with the ones that fired filled in.
 *
 * An empty stage is drawn, not omitted. "Reconnaissance was not observed" and
 * "reconnaissance did not happen" are different statements, and the reader has
 * to be able to tell which one they are looking at.
 */
function StageTrack({ track, reached }) {
  return (
    <Box sx={{
      display: 'flex', alignItems: 'stretch', flexWrap: 'wrap',
      border: `1px solid ${RULE}`, borderRadius: 1, overflow: 'hidden', mb: 1.5,
    }}>
      {track.map((stage, i) => {
        const hit = reached.get(stage.tactic_id);
        return (
          <Box
            key={stage.tactic_id}
            sx={{
              flex: '1 1 150px', minWidth: 0, px: 1.4, py: 1,
              borderLeft: i ? `1px solid ${RULE}` : 'none',
              backgroundColor: hit ? PAPER : PANEL_ALT,
              // A filled stage carries a top rule in the severity of the worst
              // finding in it: colour that answers a question.
              borderTop: hit
                ? `3px solid ${SEVERITY_INK[hit.worstSeverity] ?? INK_SOFT}`
                : `3px solid ${RULE_STRONG}`,
            }}
          >
            <Typography sx={{
              fontSize: 9, fontFamily: MONO, color: GREY_MUTED, letterSpacing: 0.5,
            }}>
              {stage.tactic_id}
            </Typography>
            <Typography sx={{
              fontSize: 12, fontWeight: hit ? 700 : 500,
              color: hit ? INK : GREY_MUTED, lineHeight: 1.25,
            }}>
              {stage.tactic}
            </Typography>
            {hit ? (
              <>
                <Typography sx={{ fontSize: 10.5, color: INK_SOFT, mt: 0.3 }}>
                  {hit.findings.length} finding{hit.findings.length === 1 ? '' : 's'}
                </Typography>
                <Typography sx={{ fontSize: 9.5, fontFamily: MONO, color: GREY }}>
                  {clock(hit.first_seen) ?? 'no packet time'}
                </Typography>
              </>
            ) : (
              <Typography sx={{ fontSize: 10, color: GREY_MUTED, mt: 0.3, lineHeight: 1.3 }}>
                not observed
              </Typography>
            )}
          </Box>
        );
      })}
    </Box>
  );
}

function TechniqueChip({ technique }) {
  return (
    <Box
      component="a"
      href={technique.url}
      target="_blank"
      rel="noopener noreferrer"
      title={technique.note || `${technique.tactic} — ${technique.name}`}
      sx={{
        display: 'inline-flex', gap: 0.6, alignItems: 'baseline',
        px: 0.8, py: 0.25, borderRadius: 0.75, textDecoration: 'none',
        border: `1px solid ${RULE}`, backgroundColor: CYAN_WASH,
        '&:hover': { borderColor: CYAN },
      }}
    >
      <Box component="span" sx={{
        fontFamily: MONO, fontSize: 10.5, fontWeight: 700, color: CYAN,
      }}>
        {technique.id}
      </Box>
      <Box component="span" sx={{ fontSize: 10.5, color: INK_SOFT }}>
        {technique.name}
      </Box>
    </Box>
  );
}

function FindingRow({ row }) {
  return (
    <Box sx={{
      display: 'flex', gap: 1, alignItems: 'stretch', py: 0.55,
      borderTop: `1px solid ${RULE}`,
    }}>
      <Box sx={{
        width: 3, flexShrink: 0, borderRadius: 2,
        backgroundColor: SEVERITY_INK[row.severity] ?? GREY_MUTED,
      }} />
      <Box sx={{ minWidth: 0, flexGrow: 1 }}>
        <Typography sx={{ fontSize: 12, color: INK, lineHeight: 1.35 }}>
          {row.title}
        </Typography>
        <Typography sx={{ fontSize: 10, fontFamily: MONO, color: GREY, lineHeight: 1.4 }}>
          {row.rule_id}
          {row.peer ? ` · with ${row.peer}` : ''}
          {row.first_seen ? ` · ${clock(row.first_seen)}` : ''}
        </Typography>
        {row.why_no_technique && (
          <Typography sx={{ fontSize: 10, color: GREY_MUTED, lineHeight: 1.4, mt: 0.2 }}>
            {row.why_no_technique}
          </Typography>
        )}
      </Box>
    </Box>
  );
}

function Fold({ label, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <Box sx={{ mt: 1.5 }}>
      <Box
        onClick={() => setOpen((v) => !v)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setOpen((v) => !v); }}
        sx={{
          display: 'flex', alignItems: 'center', gap: 0.6, cursor: 'pointer',
          color: GREY, '&:hover': { color: INK },
        }}
      >
        <ExpandMoreIcon sx={{
          fontSize: 17,
          transform: open ? 'rotate(0deg)' : 'rotate(-90deg)',
          transition: 'transform 0.2s',
        }} />
        <Typography sx={{ fontSize: 11.5, fontWeight: 600 }}>{label}</Typography>
      </Box>
      <Collapse in={open}>{children}</Collapse>
    </Box>
  );
}

function AttackScenario({ data }) {
  const [selected, setSelected] = useState(null);

  // Memoised rather than written inline: `data?.hosts ?? []` builds a fresh
  // array on every render when the field is absent, which would make the two
  // memos below recompute every time regardless of whether anything changed.
  const hosts = useMemo(() => data?.hosts ?? [], [data]);
  const host = useMemo(
    () => hosts.find((h) => h.host === selected) ?? hosts[0] ?? null,
    [hosts, selected],
  );

  const reached = useMemo(() => {
    const map = new Map();
    (host?.stages ?? []).forEach((stage) => {
      map.set(stage.tactic_id, {
        ...stage,
        worstSeverity: stage.findings.reduce(
          (worst, f) => (f.severity_rank > (worst?.severity_rank ?? -1) ? f : worst),
          null,
        )?.severity,
      });
    });
    return map;
  }, [host]);

  if (!data) return null;

  if (!hosts.length) {
    return (
      <Typography sx={{ fontSize: 12.5, color: GREY, py: 1.5 }}>
        No host in this capture carries a finding, so there is no sequence to
        assemble. That is not a clean bill of health — it means nothing crossed
        a threshold.
      </Typography>
    );
  }

  return (
    <Box>
      {/* Which machine. Ranked worst first by the server, so the default
          selection is already the one that matters. */}
      <Box sx={{ display: 'flex', gap: 0.7, flexWrap: 'wrap', mb: 1.5 }}>
        {hosts.slice(0, 8).map((h) => {
          const active = h.host === host?.host;
          return (
            <Box
              key={h.host}
              onClick={() => setSelected(h.host)}
              sx={{
                px: 1, py: 0.4, borderRadius: 0.75, cursor: 'pointer',
                border: `1px solid ${active ? INK : RULE}`,
                backgroundColor: active ? INK : PAPER,
                display: 'flex', gap: 0.6, alignItems: 'baseline',
                '&:hover': { borderColor: active ? INK : RULE_STRONG },
              }}
            >
              <Typography sx={{
                fontFamily: MONO, fontSize: 11.5,
                color: active ? PAPER : INK_SOFT,
              }}>
                {h.host}
              </Typography>
              <Typography sx={{
                fontSize: 10, fontWeight: 700,
                color: active ? PAPER : (SEVERITY_INK[h.worst_severity] ?? GREY),
              }}>
                {h.finding_count}
              </Typography>
            </Box>
          );
        })}
      </Box>

      {host && (
        <>
          <Typography sx={{
            fontSize: 13.5, color: INK, fontWeight: 600, mb: 1.2, lineHeight: 1.5,
            borderLeft: `3px solid ${SEVERITY_INK[host.worst_severity] ?? RULE_STRONG}`,
            pl: 1.3,
          }}>
            {host.summary}
          </Typography>

          <StageTrack track={data.observable ?? []} reached={reached} />

          {/* Where the clock contradicts the ordering. Red, and never folded
              away — this is usually a fact about the exhibit rather than about
              the attacker, and it belongs in the report either way. */}
          {host.time_conflicts?.map((conflict) => (
            <Box
              key={`${conflict.expected_first}-${conflict.observed_first}`}
              sx={{
                p: 1.2, mb: 1.5, borderRadius: 1,
                border: `1px solid ${CRITICAL}`, backgroundColor: PAPER,
              }}
            >
              <Typography sx={{ fontSize: 11.5, color: CRITICAL, fontWeight: 700 }}>
                Recorded out of sequence
              </Typography>
              <Typography sx={{ fontSize: 11.5, color: INK_SOFT, lineHeight: 1.5 }}>
                {conflict.note}
              </Typography>
            </Box>
          ))}

          {host.stages.map((stage) => (
            <Box key={stage.tactic_id} sx={{ mb: 1.5 }}>
              <Box sx={{
                display: 'flex', gap: 1, alignItems: 'baseline',
                flexWrap: 'wrap', mb: 0.5,
              }}>
                <Typography sx={{ fontSize: 12, fontWeight: 700, color: INK }}>
                  {stage.tactic}
                </Typography>
                {stage.techniques.map((t) => (
                  <TechniqueChip key={t.id} technique={t} />
                ))}
              </Box>
              {stage.findings.map((row) => <FindingRow key={row.id} row={row} />)}
            </Box>
          ))}

          {host.unclassified?.length > 0 && (
            <Fold label={`${host.unclassified.length} supporting finding${
              host.unclassified.length === 1 ? '' : 's'} with no ATT&CK technique`}>
              <Box sx={{ pl: 2.8, pt: 0.5 }}>
                {host.unclassified.map((row) => <FindingRow key={row.id} row={row} />)}
              </Box>
            </Fold>
          )}
        </>
      )}

      <Fold label={`What network traffic cannot show — ${
        data.unobservable?.length ?? 0} of ${data.tactics_total} ATT&CK tactics`}>
        <Box sx={{
          pl: 2.8, pt: 0.8, display: 'grid', gap: 0.7,
          gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' },
        }}>
          {(data.unobservable ?? []).map((row) => (
            <Box key={row.tactic_id} sx={{
              p: 1, borderRadius: 0.75, backgroundColor: PANEL,
              border: `1px solid ${RULE}`,
            }}>
              <Typography sx={{ fontSize: 11.5, fontWeight: 600, color: INK_SOFT }}>
                {row.tactic}
                <Box component="span" sx={{
                  fontFamily: MONO, fontSize: 9.5, color: GREY_MUTED, ml: 0.7,
                }}>
                  {row.tactic_id}
                </Box>
              </Typography>
              <Typography sx={{ fontSize: 10.5, color: GREY, lineHeight: 1.45 }}>
                {row.reason}
              </Typography>
            </Box>
          ))}
        </Box>
      </Fold>

      <Typography sx={{ fontSize: 11, color: GREY_MUTED, mt: 1.5, lineHeight: 1.5 }}>
        {data.basis} {data.limits}
      </Typography>
    </Box>
  );
}

export default AttackScenario;
