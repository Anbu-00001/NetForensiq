// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
import { useEffect, useRef, useState } from 'react';
import {
  Box, Typography, Button, TextField, Alert, LinearProgress,
  MenuItem, CircularProgress,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import UploadFileOutlinedIcon from '@mui/icons-material/UploadFileOutlined';
import Sidebar from '../components/layout/Sidebar';
import TopBar from '../components/layout/TopBar';
import ClassificationBanner, { BANNER_HEIGHT } from '../components/layout/ClassificationBanner';
import { captureProgress, uploadCapture } from '../services/forensics';
import { refreshPosture } from '../services/posture';
import { useCurrentUser, canActOnEvidence } from '../services/session';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, RULE, RULE_STRONG, PANEL, PANEL_ALT, PAPER,
  CYAN, CYAN_WASH, CRITICAL, MEDIUM, INTACT, MONO,
} from '../theme/tokens';

/**
 * Taking a capture into evidence, through the browser.
 *
 * The command line could already do this. That is not the same as the feature
 * existing: an officer with a capture on a USB stick and no shell account had
 * no way in, and a forensics platform whose only intake path is
 * `manage.py import_pcap` is a platform with one user.
 *
 * The shape of this form is the argument
 * -------------------------------------
 * **Origin is required and has no default.** It is the first field, not the
 * last, and nothing can be submitted without it. A default would mean the
 * system deciding on an officer's behalf what a file *is*, and every honest
 * default makes the feature useless. What the officer states here is what gets
 * recorded, and it is what the certificate later prints.
 *
 * **The file is sealed before it is read.** The hash is taken of the bytes as
 * they arrived, and analysis runs against the sealed copy — never the upload.
 * So the artefact the recorded digest describes is the artefact the findings
 * came from, which is the thing a defence expert will ask about.
 *
 * **The result is the receipt.** On success this prints the exhibit number and
 * the SHA-256 rather than a tick and a redirect, because those two strings are
 * what the officer writes in the register.
 *
 * **The receipt arrives before the analysis finishes.** Reading a real capture
 * takes minutes, and it used to happen inside this request: the page showed a
 * spinner for 102 seconds on a 46 MB file and forever if anything dropped the
 * connection (research/155). The upload now returns as soon as the exhibit is
 * sealed — which is the part the officer is waiting to be told — and the
 * reading is watched here, packet count and all, so a working import is
 * visibly different from a dead one.
 */

const MAX_BYTES = 512 * 1024 * 1024;

const ORIGINS = [
  {
    value: 'seized',
    label: 'Seized — captured from a network under investigation',
    help: 'Evidence. This is a declaration you are making at intake, and it '
        + 'will be printed on the s.63 certificate.',
    tone: CRITICAL,
  },
  {
    value: 'reference',
    label: 'Reference — real traffic from a published corpus',
    help: 'Real traffic, but not evidence in any case. Used to test detection '
        + 'against traffic this project did not create.',
    tone: MEDIUM,
  },
  {
    value: 'synthetic',
    label: 'Synthetic — generated, not evidence',
    help: 'Made-up traffic for demonstration or testing. Everything derived '
        + 'from it is marked as demonstration material throughout.',
    tone: GREY_MUTED,
  },
];

function Field({ label, hint, ...rest }) {
  return (
    <Box sx={{ mb: 1.8 }}>
      <Typography sx={{
        fontSize: 10.5, letterSpacing: 0.8, color: INK_SOFT,
        fontWeight: 700, mb: 0.5,
      }}>
        {label}
      </Typography>
      <TextField
        fullWidth size="small"
        sx={{
          '& .MuiOutlinedInput-root': {
            backgroundColor: PAPER, fontSize: 13,
            '& fieldset': { borderColor: RULE },
            '&:hover fieldset': { borderColor: RULE_STRONG },
            '&.Mui-focused fieldset': { borderColor: CYAN },
          },
        }}
        {...rest}
      />
      {hint && (
        <Typography sx={{ fontSize: 10.5, color: GREY, mt: 0.4, lineHeight: 1.45 }}>
          {hint}
        </Typography>
      )}
    </Box>
  );
}

function bytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB'];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
}

/**
 * What the import is doing, while it does it.
 *
 * Every figure here is reported by the process doing the work, and the panel
 * says which of them is an estimate. The one thing it must never do is imply
 * that an analysis finished: until the session leaves "running" there are no
 * findings to speak of, which is why the counts it shows are packets read and
 * conversations written, not detections.
 */
function ImportProgress({ progress }) {
  if (!progress) {
    return (
      <Box sx={{ mt: 1.5 }}>
        <LinearProgress sx={{ height: 3, backgroundColor: RULE }} />
        <Typography sx={{ fontSize: 11, color: GREY, mt: 0.6 }}>
          Starting the import…
        </Typography>
      </Box>
    );
  }

  if (progress.state === 'failed') {
    return (
      <Alert severity="error" sx={{ mt: 1.5, fontSize: 12 }}>
        {progress.error_message
          || 'The import stopped before it finished. The exhibit is sealed and '
            + 'can be imported again.'}
      </Alert>
    );
  }

  if (progress.state !== 'running') {
    return (
      <Box sx={{ mt: 1.5, pt: 1.5, borderTop: `1px solid ${RULE}` }}>
        <Typography sx={{ fontSize: 12, color: INK, fontWeight: 600, mb: 0.5 }}>
          Read and analysed
        </Typography>
        <Typography sx={{ fontSize: 11.5, fontFamily: MONO, color: INK }}>
          {Number(progress.packet_count).toLocaleString()} packets
          {' · '}
          {Number(progress.flow_count).toLocaleString()} conversations
        </Typography>
      </Box>
    );
  }

  const percent = progress.percent_estimate;
  return (
    <Box sx={{ mt: 1.5, pt: 1.5, borderTop: `1px solid ${RULE}` }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.6 }}>
        <Typography sx={{ fontSize: 12, color: INK, fontWeight: 600 }}>
          {progress.stage_label || 'Working'}
        </Typography>
        {percent != null && progress.stage === 'reading' && (
          <Typography sx={{ fontSize: 11, color: GREY, fontFamily: MONO }}>
            {percent}% of the file (estimate)
          </Typography>
        )}
      </Box>
      <LinearProgress
        variant={percent != null && progress.stage === 'reading'
          ? 'determinate' : 'indeterminate'}
        value={percent ?? 0}
        sx={{
          height: 3, backgroundColor: RULE,
          '& .MuiLinearProgress-bar': { backgroundColor: CYAN },
        }}
      />
      <Typography sx={{ fontSize: 11, color: GREY, mt: 0.6, fontFamily: MONO }}>
        {Number(progress.packets_read).toLocaleString()} packets read
        {' · '}
        {Number(progress.flows_written).toLocaleString()} conversations written
      </Typography>
      <Typography sx={{ fontSize: 11, color: GREY_MUTED, mt: 0.4, lineHeight: 1.5 }}>
        This continues on the server. You can leave this page, sign out, or
        close the browser — the import is not this window.
      </Typography>
    </Box>
  );
}

function ImportPage() {
  const navigate = useNavigate();
  const user = useCurrentUser();
  const mayImport = canActOnEvidence(user);

  const input = useRef(null);
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [origin, setOrigin] = useState('');
  const [meta, setMeta] = useState({
    name: '', home_net: '', case_reference: '', fir_number: '',
    police_station: '', seized_from: '', acquisition_notes: '',
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [progress, setProgress] = useState(null);

  // Watch the import that the upload handed to a separate process.
  //
  // Two seconds: fast enough that the figures visibly move, slow enough that
  // it is nothing next to the work being reported on. Polling stops the
  // moment the session is no longer running, and on unmount — a page left
  // open on a finished import must not keep asking.
  useEffect(() => {
    const id = result?.session_id;
    if (!id) return undefined;
    let live = true;

    const ask = async () => {
      try {
        const data = await captureProgress(id);
        if (!live) return;
        setProgress(data);
        if (data.state !== 'running') clearInterval(timer);
      } catch {
        // A failed poll says nothing about the import, which is running in
        // another process. The last figures stay on screen rather than being
        // replaced by an error about the watching.
      }
    };

    const timer = setInterval(ask, 2000);
    ask();
    return () => { live = false; clearInterval(timer); };
  }, [result?.session_id]);

  const set = (key) => (event) => setMeta((m) => ({ ...m, [key]: event.target.value }));

  const choose = (chosen) => {
    setError('');
    setResult(null);
    setProgress(null);
    if (!chosen) return;
    if (chosen.size > MAX_BYTES) {
      setError(
        `That capture is ${bytes(chosen.size)}. The browser path accepts up to `
        + `${bytes(MAX_BYTES)} — a larger file has to be imported with `
        + `"manage.py import_pcap", which has no limit.`,
      );
      return;
    }
    setFile(chosen);
  };

  const submit = async (event) => {
    event.preventDefault();
    setError('');
    if (!file) { setError('Choose a capture file first.'); return; }
    if (!origin) { setError('State where this capture came from.'); return; }

    const body = new FormData();
    body.append('file', file);
    body.append('provenance', origin);
    Object.entries(meta).forEach(([key, value]) => {
      if (value.trim()) body.append(key, value.trim());
    });

    setBusy(true);
    setProgress(null);
    try {
      const data = await uploadCapture(body);
      setResult(data);
      setFile(null);
      // The sidebar's exhibit and encryption counts are now out of date.
      refreshPosture();
    } catch (err) {
      setError(
        err?.response?.data?.detail
        ?? 'The upload failed before the file was taken into evidence.',
      );
    } finally {
      setBusy(false);
    }
  };

  const chosenOrigin = ORIGINS.find((o) => o.value === origin);

  return (
    <Box sx={{ minHeight: '100vh', backgroundColor: PAPER, pt: `${BANNER_HEIGHT}px` }}>
      <ClassificationBanner fixed />
      <Box sx={{ display: 'flex' }}>
        <Sidebar />
        <Box sx={{ flexGrow: 1, minWidth: 0 }}>
          <TopBar />
          <Box sx={{ p: 2.5, maxWidth: 900 }}>
            <Typography sx={{ fontSize: 19, fontWeight: 700, color: INK, mb: 0.3 }}>
              Take a capture into evidence
            </Typography>
            <Typography sx={{ fontSize: 12.5, color: GREY, mb: 2.5, lineHeight: 1.6 }}>
              The file is hashed and sealed before anything reads it, and the
              analysis runs against the sealed copy rather than the upload —
              so the exhibit the recorded digest describes is the exhibit the
              findings came from.
            </Typography>

            {!mayImport && (
              <Alert severity="warning" sx={{ mb: 2, fontSize: 12.5 }}>
                Your clearance is {user?.role ?? 'unknown'}. Taking evidence into
                custody requires Investigator clearance — an examiner reads what
                the investigating officer seized, and does not seize.
              </Alert>
            )}

            {result && (
              <Box sx={{
                p: 2, mb: 2.5, borderRadius: 1,
                border: `1px solid ${INTACT}`, backgroundColor: PANEL,
              }}>
                <Typography sx={{ fontSize: 13, fontWeight: 700, color: INTACT, mb: 1 }}>
                  Sealed into evidence
                </Typography>
                {[
                  ['Exhibit', result.exhibit_number],
                  ['SHA-256', result.sha256],
                  ['MD5', result.md5],
                  ['Origin', result.provenance_label],
                  ['Custody entries', result.custody_events],
                ].map(([label, value]) => (
                  <Box key={label} sx={{ display: 'flex', gap: 1.5, mb: 0.4 }}>
                    <Typography sx={{
                      fontSize: 11, color: GREY_MUTED, minWidth: 116, flexShrink: 0,
                    }}>
                      {label}
                    </Typography>
                    <Typography sx={{
                      fontSize: 11.5, fontFamily: MONO, color: INK,
                      wordBreak: 'break-all',
                    }}>
                      {value}
                    </Typography>
                  </Box>
                ))}
                <Typography sx={{ fontSize: 11, color: GREY, mt: 1, lineHeight: 1.5 }}>
                  Write the exhibit number and the SHA-256 in the register. The
                  digest is of the file as it arrived, so anyone handed the same
                  capture can reproduce it.
                </Typography>

                <ImportProgress progress={progress} />

                <Button
                  size="small" variant="contained"
                  disabled={progress?.state === 'running'}
                  onClick={() => navigate(`/dashboard?session=${result.session_id}`)}
                  sx={{
                    mt: 1.5, textTransform: 'none', fontSize: 12.5,
                    backgroundColor: INK, '&:hover': { backgroundColor: INK_SOFT },
                  }}
                >
                  {progress?.state === 'running'
                    ? 'Reading the capture…'
                    : `Open ${result.session_name}`}
                </Button>
              </Box>
            )}

            {error && (
              <Alert severity="error" sx={{ mb: 2, fontSize: 12.5 }}>{error}</Alert>
            )}

            <form onSubmit={submit}>
              {/* The file */}
              <Box
                onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragging(false);
                  choose(e.dataTransfer.files?.[0]);
                }}
                onClick={() => input.current?.click()}
                sx={{
                  p: 3, mb: 2.5, borderRadius: 1, textAlign: 'center',
                  cursor: mayImport ? 'pointer' : 'not-allowed',
                  border: `1.5px dashed ${dragging ? CYAN : RULE_STRONG}`,
                  backgroundColor: dragging ? CYAN_WASH : PANEL,
                  opacity: mayImport ? 1 : 0.55,
                }}
              >
                <input
                  ref={input} type="file" hidden
                  accept=".pcap,.pcapng,.cap"
                  disabled={!mayImport}
                  onChange={(e) => choose(e.target.files?.[0])}
                />
                <UploadFileOutlinedIcon sx={{ fontSize: 30, color: GREY, mb: 0.5 }} />
                <Typography sx={{ fontSize: 13.5, color: INK, fontWeight: 600 }}>
                  {file ? file.name : 'Drop a .pcap or .pcapng here, or click to choose'}
                </Typography>
                <Typography sx={{ fontSize: 11.5, color: GREY, mt: 0.3 }}>
                  {file
                    ? `${bytes(file.size)} — the file is checked by its magic
                       number, not its extension`.replace(/\s+/g, ' ')
                    : `Up to ${bytes(MAX_BYTES)}`}
                </Typography>
              </Box>

              {/* Origin — required, first, undefaulted. */}
              <Box sx={{ mb: 2.5 }}>
                <Typography sx={{
                  fontSize: 10.5, letterSpacing: 0.8, color: INK_SOFT,
                  fontWeight: 700, mb: 0.5,
                }}>
                  WHERE THIS CAPTURE CAME FROM — REQUIRED
                </Typography>
                <TextField
                  select fullWidth size="small" value={origin}
                  disabled={!mayImport}
                  onChange={(e) => setOrigin(e.target.value)}
                  sx={{
                    '& .MuiOutlinedInput-root': {
                      backgroundColor: PAPER, fontSize: 13,
                      '& fieldset': { borderColor: origin ? RULE : RULE_STRONG },
                    },
                  }}
                >
                  {ORIGINS.map((option) => (
                    <MenuItem key={option.value} value={option.value} sx={{ fontSize: 13 }}>
                      {option.label}
                    </MenuItem>
                  ))}
                </TextField>
                <Typography sx={{
                  fontSize: 11, mt: 0.5, lineHeight: 1.5,
                  color: chosenOrigin ? chosenOrigin.tone : GREY,
                  fontWeight: chosenOrigin ? 600 : 400,
                }}>
                  {chosenOrigin
                    ? chosenOrigin.help
                    : 'There is no default. The system will not decide on your '
                      + 'behalf what this file is.'}
                </Typography>
              </Box>

              <Box sx={{
                display: 'grid', gap: 0,
                gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' },
                columnGap: 2,
              }}>
                <Field
                  label="SESSION NAME" value={meta.name} onChange={set('name')}
                  disabled={!mayImport}
                  placeholder="Taken from the filename if left blank"
                />
                <Field
                  label="MONITORED NETWORK" value={meta.home_net}
                  onChange={set('home_net')} disabled={!mayImport}
                  placeholder="10.0.0.0/8, 192.168.1.0/24"
                  hint="Which addresses are inside. Everything about direction —
                        egress, exfiltration, who is the victim — depends on this."
                />
                <Field
                  label="CASE REFERENCE" value={meta.case_reference}
                  onChange={set('case_reference')} disabled={!mayImport}
                />
                <Field
                  label="FIR NUMBER" value={meta.fir_number}
                  onChange={set('fir_number')} disabled={!mayImport}
                  hint="Leave blank if there is no FIR. A placeholder here ends up
                        printed on a certificate."
                />
                <Field
                  label="POLICE STATION" value={meta.police_station}
                  onChange={set('police_station')} disabled={!mayImport}
                />
                <Field
                  label="SEIZED FROM" value={meta.seized_from}
                  onChange={set('seized_from')} disabled={!mayImport}
                  placeholder="Where the capture was taken"
                />
              </Box>

              <Field
                label="ACQUISITION NOTES" value={meta.acquisition_notes}
                onChange={set('acquisition_notes')} disabled={!mayImport}
                multiline minRows={2}
                hint="How it was captured, on what, by whom. This is written into
                      the chain of custody and cannot be edited afterwards."
              />

              {busy && (
                <Box sx={{ mb: 2 }}>
                  <LinearProgress sx={{
                    height: 3, backgroundColor: PANEL_ALT,
                    '& .MuiLinearProgress-bar': { backgroundColor: CYAN },
                  }} />
                  <Typography sx={{ fontSize: 11.5, color: GREY, mt: 0.6 }}>
                    Sealing, then reading every packet. A large capture takes a
                    while — this does not run in the background, because a
                    half-imported exhibit is worse than a slow one.
                  </Typography>
                </Box>
              )}

              <Button
                type="submit" variant="contained"
                disabled={busy || !mayImport || !file || !origin}
                startIcon={busy
                  ? <CircularProgress size={15} sx={{ color: PAPER }} />
                  : null}
                sx={{
                  textTransform: 'none', fontSize: 13.5, fontWeight: 600,
                  px: 3, py: 1, backgroundColor: INK,
                  '&:hover': { backgroundColor: INK_SOFT },
                }}
              >
                {busy ? 'Sealing and analysing…' : 'Seal and analyse'}
              </Button>
            </form>
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

export default ImportPage;
