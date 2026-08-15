import { useEffect, useState } from 'react';
import {
  Box, Typography, Chip, Button, CircularProgress, Alert, Collapse, TextField,
} from '@mui/material';
import Sidebar from '../components/layout/Sidebar';
import TopBar from '../components/layout/TopBar';
import {
  listDetections, triageDetection, listThresholds, unwrap, SEVERITY_COLOR,
} from '../services/forensics';

const TRIAGE_ACTIONS = [
  { key: 'confirmed', label: 'Confirm', color: '#FF6A2B' },
  { key: 'dismissed', label: 'Dismiss (false positive)', color: '#7A8699' },
  { key: 'escalated', label: 'Escalate', color: '#FF3B5C' },
];

function DetectionCard({ detection, onTriaged }) {
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const colour = SEVERITY_COLOR[detection.severity] ?? '#7A8699';

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
      border: '1px solid rgba(255,255,255,0.07)',
      backgroundColor: 'rgba(255,255,255,0.02)',
      borderLeft: `3px solid ${colour}`,
    }}>
      <Box
        onClick={() => setOpen((v) => !v)}
        sx={{
          p: 2, cursor: 'pointer', display: 'flex', alignItems: 'center',
          gap: 1.5, flexWrap: 'wrap',
          '&:hover': { backgroundColor: 'rgba(255,255,255,0.03)' },
        }}
      >
        <Chip label={detection.severity} size="small" sx={{
          backgroundColor: `${colour}22`, color: colour, fontWeight: 700,
          fontSize: 11, textTransform: 'uppercase',
        }} />
        <Typography sx={{ fontSize: 14, color: '#E5E7EB', flexGrow: 1, minWidth: 220 }}>
          {detection.title}
        </Typography>
        <Chip label={detection.rule_id} size="small" sx={{
          backgroundColor: 'rgba(255,255,255,0.05)',
          color: 'rgba(229,231,235,0.6)', fontSize: 10.5, fontFamily: 'monospace',
        }} />
        {detection.triage_status !== 'new' && (
          <Chip label={detection.triage_status} size="small" sx={{
            backgroundColor: 'rgba(0,230,138,0.14)', color: '#00E68A', fontSize: 10.5,
          }} />
        )}
      </Box>

      <Collapse in={open}>
        <Box sx={{ px: 2, pb: 2 }}>
          <Typography sx={{
            fontSize: 13, color: 'rgba(229,231,235,0.75)', lineHeight: 1.65, mb: 1.5,
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
            backgroundColor: 'rgba(0,0,0,0.35)',
            border: '1px solid rgba(255,255,255,0.06)',
          }}>
            <Typography sx={{
              fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.6,
              color: 'rgba(229,231,235,0.4)', mb: 0.8,
            }}>
              Evidence — observed values, thresholds and their provenance
            </Typography>
            <Box component="pre" sx={{
              m: 0, fontSize: 11.5, fontFamily: 'monospace', whiteSpace: 'pre-wrap',
              color: 'rgba(229,231,235,0.75)', maxHeight: 260, overflow: 'auto',
            }}>
              {JSON.stringify(detection.evidence, null, 2)}
            </Box>
          </Box>

          {detection.triage_status === 'new' ? (
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
              <TextField
                size="small" placeholder="Analyst note (optional)"
                value={note} onChange={(e) => setNote(e.target.value)}
                sx={{
                  flexGrow: 1, minWidth: 200,
                  '& .MuiInputBase-input': { fontSize: 12.5, color: '#E5E7EB' },
                  '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(255,255,255,0.12)' },
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
            <Typography sx={{ fontSize: 12, color: 'rgba(229,231,235,0.5)' }}>
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
  const [detections, setDetections] = useState([]);
  const [thresholds, setThresholds] = useState([]);
  const [showThresholds, setShowThresholds] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([listDetections(), listThresholds()])
      .then(([d, t]) => {
        setDetections(unwrap(d));
        setThresholds(t);
      })
      .finally(() => setLoading(false));
  }, []);

  const replace = (updated) =>
    setDetections((prev) => prev.map((d) => (d.id === updated.id ? updated : d)));

  const pending = detections.filter((d) => d.triage_status === 'new').length;

  return (
    <Box sx={{ display: 'flex', backgroundColor: '#080B14', minHeight: '100vh' }}>
      <Sidebar />
      <Box sx={{ flexGrow: 1, minWidth: 0 }}>
        <TopBar />
        <Box sx={{ p: 2.5 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 0.5, flexWrap: 'wrap' }}>
            <Typography sx={{ fontSize: 20, fontWeight: 700, color: '#E5E7EB' }}>
              Findings
            </Typography>
            <Chip label={`${pending} awaiting review`} size="small" sx={{
              backgroundColor: 'rgba(255,176,32,0.15)', color: '#FFB020', fontSize: 11.5,
            }} />
            <Box sx={{ flexGrow: 1 }} />
            <Button size="small" onClick={() => setShowThresholds((v) => !v)}
              sx={{ fontSize: 12, color: 'rgba(229,231,235,0.6)' }}>
              {showThresholds ? 'Hide' : 'Show'} detection thresholds
            </Button>
          </Box>
          <Typography sx={{ fontSize: 12.5, color: 'rgba(229,231,235,0.45)', mb: 2.5 }}>
            Nothing here is auto-actioned. Each finding is a prompt for an officer to look,
            and the decision recorded against it is theirs.
          </Typography>

          <Collapse in={showThresholds}>
            <Box sx={{
              mb: 2.5, p: 2, borderRadius: 2,
              border: '1px solid rgba(255,255,255,0.07)',
              backgroundColor: 'rgba(255,255,255,0.02)',
            }}>
              {thresholds.map((t) => (
                <Box key={t.key} sx={{ mb: 1.2 }}>
                  <Typography sx={{ fontSize: 12.5, fontFamily: 'monospace', color: '#00D4FF' }}>
                    {t.key} = {String(t.value)}
                    {t.is_heuristic && (
                      <Chip label="our heuristic" size="small" sx={{
                        ml: 1, height: 17, fontSize: 10,
                        backgroundColor: 'rgba(255,176,32,0.15)', color: '#FFB020',
                      }} />
                    )}
                  </Typography>
                  <Typography sx={{ fontSize: 11.5, color: 'rgba(229,231,235,0.45)' }}>
                    {t.source}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Collapse>

          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
              <CircularProgress sx={{ color: '#00D4FF' }} />
            </Box>
          ) : !detections.length ? (
            <Alert severity="info">
              No findings yet. Import a capture and run detection from the dashboard.
            </Alert>
          ) : (
            detections.map((d) => (
              <DetectionCard key={d.id} detection={d} onTriaged={replace} />
            ))
          )}
        </Box>
      </Box>
    </Box>
  );
}

export default DetectionsPage;
