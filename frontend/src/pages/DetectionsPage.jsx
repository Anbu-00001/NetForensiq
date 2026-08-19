import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Box, Typography, Chip, Button, CircularProgress, Alert, Collapse, TextField,
} from '@mui/material';
import { describeError } from '../services/api';
import Sidebar from '../components/layout/Sidebar';
import SessionTranscript from '../components/transcript/SessionTranscript';
import ClassificationBanner, { BANNER_HEIGHT } from '../components/layout/ClassificationBanner';
import { GUJARATI } from '../i18n/gujarati';
import TopBar from '../components/layout/TopBar';
import {
  listAllDetections, triageDetection, listThresholds, unwrap, SEVERITY_COLOR,
} from '../services/forensics';
import { useCurrentUser, canActOnEvidence } from '../services/session';

// How many findings to put in the DOM at once. Not a limit on what is
// loaded or counted — see the note where it is used.
const RENDER_BATCH = 100;

const TRIAGE_ACTIONS = [
  { key: 'confirmed', label: 'Confirm', color: '#A84D08' },
  { key: 'dismissed', label: 'Dismiss (false positive)', color: '#5F656D' },
  { key: 'escalated', label: 'Escalate', color: '#B3261E' },
];

/**
 * The MITRE ATT&CK classification for one finding.
 *
 * Why it is on the card and not on a slide
 * ----------------------------------------
 * "Automated attack classification" is a stated bonus objective, and the
 * mapping has existed on the API since it was built — but nothing rendered it,
 * so a reader of the interface had no way to know it was there. A capability
 * only the source code knows about is not a capability that has been
 * delivered.
 *
 * Two things this is careful about. The identifier is a link, because the
 * whole value of a shared vocabulary is that someone can check the claim
 * against attack.mitre.org in ten seconds rather than trust our label. And
 * where a rule maps to no technique, the sentence explaining why is printed
 * instead of leaving a blank — a blank reads as an oversight, and somebody
 * would eventually "fix" it by guessing an identifier.
 */
function AttackMapping({ mapping }) {
  if (!mapping) return null;
  const techniques = mapping.techniques ?? [];

  return (
    <Box sx={{ mb: 1.5 }}>
      <Typography sx={{
        fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.6,
        color: '#5A6068', mb: 0.8,
      }}>
        MITRE ATT&amp;CK
      </Typography>

      {techniques.length ? (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.8 }}>
          {techniques.map((t) => (
            <Box
              key={t.id}
              component="a"
              href={t.url}
              target="_blank"
              rel="noopener noreferrer"
              title={t.note || `${t.tactic} — ${t.name}`}
              sx={{
                display: 'inline-flex', alignItems: 'baseline', gap: 0.7,
                px: 1, py: 0.5, borderRadius: 1,
                border: '1px solid #E2E5E9', backgroundColor: '#FFFFFF',
                textDecoration: 'none',
                '&:hover': { borderColor: '#076E7C', backgroundColor: '#E6F4F7' },
              }}
            >
              <Box component="span" sx={{
                fontFamily: "'JetBrains Mono', monospace", fontSize: 11.5,
                fontWeight: 700, color: '#076E7C',
              }}>
                {t.id}
              </Box>
              <Box component="span" sx={{ fontSize: 11.5, color: '#2B3138' }}>
                {t.name}
              </Box>
              <Box component="span" sx={{ fontSize: 10, color: '#5F656D' }}>
                {t.tactic}
              </Box>
            </Box>
          ))}
        </Box>
      ) : (
        <Typography sx={{ fontSize: 11.5, color: '#5A6068', lineHeight: 1.5 }}>
          {mapping.summary}
        </Typography>
      )}
    </Box>
  );
}

function DetectionCard({ detection, onTriaged, canTriage }) {
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const colour = SEVERITY_COLOR[detection.severity] ?? '#5F656D';

  const decide = async (statusKey) => {
    setBusy(true);
    try {
      const updated = await triageDetection(detection.id, statusKey, note);
      onTriaged(updated);
    } finally {
      setBusy(false);
    }
  };

  const heuristic = JSON.stringify(detection.evidence ?? {}).includes('[OUR HEURISTIC');

  return (
    <Box sx={{
      mb: 1.5, borderRadius: 2, overflow: 'hidden',
      border: '1px solid #E2E5E9',
      backgroundColor: '#F4F5F7',
      borderLeft: `3px solid ${colour}`,
    }}>
      {/*
        A real button, not a clickable div. An officer working three hundred
        findings with a keyboard could not open any of them, and a screen
        reader announced nothing about what the row was or whether it was
        expanded. It also gives the row an accessible name — the rule that
        fired — which is what a test can address it by.
      */}
      <Box
        role="button"
        tabIndex={0}
        aria-expanded={open}
        aria-label={`${detection.rule_id}: ${detection.title}`}
        onClick={() => setOpen((v) => !v)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setOpen((v) => !v);
          }
        }}
        sx={{
          p: 2, cursor: 'pointer', display: 'flex', alignItems: 'center',
          gap: 1.5, flexWrap: 'wrap',
          '&:hover': { backgroundColor: '#F4F5F7' },
          '&:focus-visible': {
            outline: '2px solid #076E7C', outlineOffset: -2,
          },
        }}
      >
        <Chip label={detection.severity} size="small" sx={{
          backgroundColor: `${colour}22`, color: colour, fontWeight: 700,
          fontSize: 11, textTransform: 'uppercase',
        }} />
        <Typography sx={{ fontSize: 14, color: '#111315', flexGrow: 1, minWidth: 220 }}>
          {detection.title}
        </Typography>
        <Chip label={detection.rule_id} size="small" sx={{
          backgroundColor: '#ECEEF1',
          color: '#5A6068', fontSize: 10.5, fontFamily: 'monospace',
        }} />
        {/*
          Which sealed exhibit this claim rests on. A finding is an assertion
          about traffic, and an assertion about traffic nobody can point to a
          hashed artefact for is worth nothing in court. When the exhibit is
          generated traffic, that is said in red — a demonstration finding must
          never be mistaken for a finding about a case.
        */}
        {detection.is_demonstration_only ? (
          <Chip label="DEMO DATA" size="small" sx={{
            backgroundColor: 'rgba(179,38,30,0.16)', color: '#B3261E',
            fontSize: 10.5, fontWeight: 700,
          }} />
        ) : detection.exhibit_number ? (
          <Chip label={detection.exhibit_number} size="small" sx={{
            backgroundColor: '#ECEEF1',
            color: '#5A6068', fontSize: 10.5, fontFamily: 'monospace',
          }} />
        ) : (
          // The capture was imported with --no-seal, so this finding rests on
          // a file that was never taken into custody. Saying nothing would
          // leave it looking like every other row.
          <Chip label="not in evidence" size="small" sx={{
            backgroundColor: 'rgba(138,97,0,0.14)', color: '#8A6100', fontSize: 10.5,
          }} />
        )}
        {detection.triage_status !== 'new' && (
          <Chip label={detection.triage_status} size="small" sx={{
            backgroundColor: 'rgba(27,110,60,0.14)', color: '#1B6E3C', fontSize: 10.5,
          }} />
        )}
      </Box>

      <Collapse in={open}>
        <Box sx={{ px: 2, pb: 2 }}>
          <Typography sx={{
            fontSize: 13, color: '#2B3138', lineHeight: 1.65, mb: 1.5,
          }}>
            {detection.rationale}
          </Typography>

          {heuristic && (
            <Alert severity="info" sx={{ mb: 1.5, fontSize: 12 }}>
              At least one threshold behind this finding is our own heuristic with no
              published source. It is labelled as such in the evidence below.
            </Alert>
          )}

          <Box sx={{
            p: 1.5, borderRadius: 1.5, mb: 1.5,
            backgroundColor: '#ECEEF1',
            border: '1px solid #E2E5E9',
          }}>
            <Typography sx={{
              fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.6,
              color: '#5A6068', mb: 0.8,
            }}>
              Evidence — observed values, thresholds and their provenance
            </Typography>
            <Box component="pre" sx={{
              m: 0, fontSize: 11.5, fontFamily: 'monospace', whiteSpace: 'pre-wrap',
              color: '#2B3138', maxHeight: 260, overflow: 'auto',
            }}>
              {JSON.stringify(detection.evidence, null, 2)}
            </Box>
          </Box>

          {/*
            A finding is an assertion about a conversation. Where that
            conversation is a TCP flow in a sealed exhibit, the officer can read
            it back rather than take the rule's word for what happened. Only
            offered when there is a flow behind the finding — the corroboration
            and anomaly rules are about a host across many flows, and there is
            no single conversation to show.
          */}
          <AttackMapping mapping={detection.mitre_attack} />

          {detection.flow && <SessionTranscript flowId={detection.flow} />}

          <Box sx={{ height: 12 }} />

          {detection.triage_status === 'new' && !canTriage ? (
            <Typography sx={{ fontSize: 12, color: '#5A6068' }}>
              Awaiting review. Recording a decision requires Investigator
              clearance; your account holds Viewer.
            </Typography>
          ) : detection.triage_status === 'new' ? (
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
              <TextField
                size="small" placeholder="Analyst note (optional)"
                value={note} onChange={(e) => setNote(e.target.value)}
                sx={{
                  flexGrow: 1, minWidth: 200,
                  '& .MuiInputBase-input': { fontSize: 12.5, color: '#111315' },
                  '& .MuiOutlinedInput-notchedOutline': { borderColor: '#C7CCD2' },
                }}
              />
              {TRIAGE_ACTIONS.map((a) => (
                <Button
                  key={a.key} size="small" variant="outlined" disabled={busy}
                  onClick={() => decide(a.key)}
                  sx={{
                    fontSize: 11.5, borderColor: `${a.color}55`, color: a.color,
                    '&:hover': { borderColor: a.color, backgroundColor: `${a.color}12` },
                  }}
                >
                  {a.label}
                </Button>
              ))}
            </Box>
          ) : (
            <Typography sx={{ fontSize: 12, color: '#5A6068' }}>
              Reviewed{detection.reviewed_at
                ? ` at ${new Date(detection.reviewed_at).toLocaleString()}` : ''}
              {detection.review_note ? ` — "${detection.review_note}"` : ''}
            </Typography>
          )}
        </Box>
      </Collapse>
    </Box>
  );
}

function DetectionsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const query = (searchParams.get('q') ?? '').trim().toLowerCase();
  const [detections, setDetections] = useState([]);
  const [thresholds, setThresholds] = useState([]);
  const [showThresholds, setShowThresholds] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const canTriage = canActOnEvidence(useCurrentUser());
  // Keyed by the query so a new search starts from the top of its own
  // result set. Deriving it beats syncing state to `query` in an effect,
  // which costs an extra render on every keystroke.
  const [rendered, setRendered] = useState({ q: '', n: RENDER_BATCH });

  // Loaded independently. Under Promise.all a slow or failing findings
  // request also emptied the threshold panel — so the one page whose purpose
  // is "every threshold is published" silently published none, and the
  // failure looked like a UI regression rather than a request problem.
  useEffect(() => {
    let live = true;

    listAllDetections()
      .then((d) => { if (live) setDetections(unwrap(d)); })
      .catch((err) => { if (live) setError(describeError(err, 'Could not load findings.')); })
      .finally(() => { if (live) setLoading(false); });

    listThresholds()
      .then((t) => { if (live) setThresholds(t); })
      .catch(() => {});

    return () => { live = false; };
  }, []);

  const replace = (updated) =>
    setDetections((prev) => prev.map((d) => (d.id === updated.id ? updated : d)));

  // Filtering happens here rather than server-side because the finding set for
  // one capture is small and already loaded; a round-trip would add latency
  // without adding accuracy.
  const visible = useMemo(() => {
    if (!query) return detections;
    return detections.filter((d) => {
      const haystack = [
        d.subject_ip, d.rule_id, d.title, d.category, d.rationale,
      ].filter(Boolean).join(' ').toLowerCase();
      return haystack.includes(query);
    });
  }, [detections, query]);

  const pending = visible.filter((d) => d.triage_status === 'new').length;

  // Every finding is loaded — the counts above are computed over all of them —
  // but rendering 343 expandable cards at once takes seconds and a real case
  // could hold thousands. The list renders in batches; the true total is
  // always stated beside it, so the page never implies it is showing more
  // than it is.
  const renderCount = rendered.q === query ? rendered.n : RENDER_BATCH;
  const shown = visible.slice(0, renderCount);
  const remaining = visible.length - shown.length;

  return (
    <Box sx={{ display: 'flex', backgroundColor: '#FFFFFF', minHeight: '100vh',
      pt: `${BANNER_HEIGHT}px` }}>
      <ClassificationBanner level="restricted" fixed />
      <Sidebar />
      <Box sx={{ flexGrow: 1, minWidth: 0 }}>
        <TopBar />
        <Box sx={{ p: 2.5 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 0.5, flexWrap: 'wrap' }}>
            <Typography sx={{ fontSize: 20, fontWeight: 700, color: '#111315' }}>
              Findings{' '}
              {/*
                A reading aid, not a translation. The English is authoritative
                everywhere; see src/i18n/gujarati.js for why the certificate PDF
                cannot carry the same glosses.
              */}
              <Box component="span" lang="gu" sx={{
                fontSize: 15, fontWeight: 500, color: '#2B3138',
              }}>
                ({GUJARATI.findings})
              </Box>
            </Typography>
            <Chip label={`${pending} awaiting review`} size="small" sx={{
              backgroundColor: 'rgba(138,97,0,0.15)', color: '#8A6100', fontSize: 11.5,
            }} />
            {query && (
              // A filter that is not visible is a filter that misleads: without
              // this the page looks like the full finding set.
              <Chip
                label={`filtered: "${query}" (${visible.length}/${detections.length})`}
                size="small" onDelete={() => setSearchParams({})}
                sx={{
                  backgroundColor: 'rgba(7,110,124,0.16)', color: '#076E7C', fontSize: 11.5,
                }}
              />
            )}
            <Box sx={{ flexGrow: 1 }} />
            <Button size="small" onClick={() => setShowThresholds((v) => !v)}
              sx={{ fontSize: 12, color: '#5A6068' }}>
              {showThresholds ? 'Hide' : 'Show'} detection thresholds
            </Button>
          </Box>
          <Typography sx={{ fontSize: 12.5, color: '#5A6068', mb: 2.5 }}>
            Nothing here is auto-actioned. Each finding is a prompt for an officer to look,
            and the decision recorded against it is theirs.
          </Typography>

          <Collapse in={showThresholds}>
            <Box sx={{
              mb: 2.5, p: 2, borderRadius: 2,
              border: '1px solid #E2E5E9',
              backgroundColor: '#F4F5F7',
            }}>
              {thresholds.map((t) => (
                <Box key={t.key} sx={{ mb: 1.2 }}>
                  <Typography component="div"
                    sx={{ fontSize: 12.5, fontFamily: 'monospace', color: '#076E7C' }}>
                    {t.key} = {String(t.value)}
                    {t.is_heuristic && (
                      <Chip label="our heuristic" size="small" sx={{
                        ml: 1, height: 17, fontSize: 10,
                        backgroundColor: 'rgba(138,97,0,0.15)', color: '#8A6100',
                      }} />
                    )}
                    {t.is_informational && (
                      // Not a test any rule performs — it decides where one
                      // conversation ends and the next begins.
                      <Chip label="aggregation, not a rule" size="small" sx={{
                        ml: 1, height: 17, fontSize: 10,
                        backgroundColor: '#E2E5E9', color: '#5A6068',
                      }} />
                    )}
                  </Typography>
                  <Typography sx={{ fontSize: 11.5, color: '#5A6068' }}>
                    {t.source}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Collapse>

          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
              <CircularProgress sx={{ color: '#076E7C' }} />
            </Box>
          ) : !visible.length ? (
            <Alert severity="info">
              {query
                ? `No findings match "${query}".`
                : 'No findings yet. Import a capture and run detection from the dashboard.'}
            </Alert>
          ) : (
            <>
              {shown.map((d) => (
                <DetectionCard
                  key={d.id} detection={d} onTriaged={replace}
                  canTriage={canTriage}
                />
              ))}
              {remaining > 0 && (
                <Box sx={{ textAlign: 'center', mt: 2 }}>
                  <Typography sx={{ fontSize: 12.5, color: '#5A6068', mb: 1 }}>
                    Showing {shown.length} of {visible.length} findings
                  </Typography>
                  <Button
                    size="small" variant="outlined"
                    onClick={() => setRendered({ q: query, n: renderCount + RENDER_BATCH })}
                    sx={{ fontSize: 12, borderColor: 'rgba(7,110,124,0.45)', color: '#076E7C' }}
                  >
                    Show {Math.min(remaining, RENDER_BATCH)} more
                  </Button>
                </Box>
              )}
            </>
          )}
        </Box>
      </Box>
    </Box>
  );
}

export default DetectionsPage;
