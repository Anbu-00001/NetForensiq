import { useEffect, useState } from 'react';
import {
  Box, Typography, Chip, Button, CircularProgress, Alert, Collapse, TextField,
} from '@mui/material';
import Sidebar from '../components/layout/Sidebar';
import ClassificationBanner, { BANNER_HEIGHT } from '../components/layout/ClassificationBanner';
import TopBar from '../components/layout/TopBar';
import {
  listEvidence, getCustodyChain, verifyEvidence, unwrap, formatBytes,
  listCertificates, issueCertificate, signCertificatePartB, downloadCertificatePdf,
} from '../services/forensics';
import { useCurrentUser, canActOnEvidence } from '../services/session';
import { describeError } from '../services/api';
import { GUJARATI } from '../i18n/gujarati';

const STATUS_STYLE = {
  sealed: { color: '#1B6E3C', label: 'Sealed — hash verified' },
  tampered: { color: '#B3261E', label: 'INTEGRITY FAILED' },
  archived: { color: '#6B7178', label: 'Archived' },
};

function Hash({ label, value }) {
  return (
    <Box sx={{ mb: 0.8 }}>
      <Typography sx={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.6,
        color: '#5A6068' }}>
        {label}
      </Typography>
      <Typography sx={{ fontSize: 11.5, fontFamily: 'monospace', color: '#111315',
        wordBreak: 'break-all' }}>
        {value || '—'}
      </Typography>
    </Box>
  );
}

/**
 * Certificates under BSA s.63(4)(c) for one exhibit.
 *
 * The two parts are deliberately separate actions. s.63(4) requires the person
 * in charge of the device AND an expert, so a certificate signed by one
 * account is incomplete and is shown as a draft until countersigned.
 */
function CertificatePanel({ record, certificates, onChanged, canAct }) {
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [expert, setExpert] = useState({ name: '', designation: '', qualification: '' });
  const [partA, setPartA] = useState({ name: '', designation: '', organisation: '' });
  const [showPartA, setShowPartA] = useState(false);

  const mine = certificates.filter((c) => c.evidence === record.id);

  const run = async (key, fn) => {
    setBusy(key);
    setError('');
    try {
      await fn();
      await onChanged();
    } catch (e) {
      setError(e?.response?.data?.detail ?? 'Request failed');
    } finally {
      setBusy('');
    }
  };

  return (
    <Box sx={{ mt: 2, pt: 1.5, borderTop: '1px solid #E2E5E9' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1, flexWrap: 'wrap' }}>
        <Typography sx={{ fontSize: 12.5, fontWeight: 600, color: '#111315' }}>
          Section 63 certificates
        </Typography>
        <Box sx={{ flexGrow: 1 }} />
        {canAct ? (
          <Button
            size="small" variant="outlined" disabled={busy === 'issue'}
            onClick={() => setShowPartA((v) => !v)}
            sx={{ fontSize: 11.5, borderColor: 'rgba(27,110,60,0.4)', color: '#1B6E3C' }}
          >
            {showPartA ? 'Cancel' : 'Issue certificate (Part A)'}
          </Button>
        ) : (
          <Typography sx={{ fontSize: 11.5, color: '#5A6068' }}>
            Issuing a certificate requires Investigator clearance
          </Typography>
        )}
      </Box>

      {/*
        Part A is a statutory declaration. It used to be issued by a single
        click sending an empty body, which recorded the officer as having
        solemnly affirmed something they were never shown and never filled in.
        The declaration is now displayed and the Schedule's fields collected
        before anything is signed.
      */}
      <Collapse in={showPartA}>
        <Box sx={{
          p: 1.5, mb: 1.5, borderRadius: 1.5,
          backgroundColor: '#ECEEF1',
          border: '1px solid rgba(27,110,60,0.25)',
        }}>
          <Typography sx={{
            fontSize: 11.5, lineHeight: 1.6, color: '#2B3138', mb: 1.2,
          }}>
            You are about to affirm, under THE SCHEDULE to the Bharatiya Sakshya
            Adhiniyam 2023, that you produced this electronic record from a device
            under your lawful control, that it was working properly, and that the
            hash values recorded are those of the record produced. Your name is
            printed on Part A of the certificate.
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
            {['name', 'designation', 'organisation'].map((field) => (
              <TextField
                key={field} size="small"
                placeholder={`Your ${field}`}
                value={partA[field]}
                onChange={(e) => setPartA({ ...partA, [field]: e.target.value })}
                sx={{
                  flexGrow: 1, minWidth: 130,
                  '& .MuiInputBase-input': { fontSize: 12, color: '#111315' },
                  '& .MuiOutlinedInput-notchedOutline': {
                    borderColor: '#C7CCD2',
                  },
                }}
              />
            ))}
            <Button
              size="small" variant="outlined"
              disabled={busy === 'issue' || !partA.name.trim()}
              onClick={() => run('issue', async () => {
                await issueCertificate(record.id, {
                  part_a_name: partA.name,
                  part_a_designation: partA.designation,
                  part_a_organisation: partA.organisation,
                });
                setShowPartA(false);
              })}
              sx={{ fontSize: 11.5, borderColor: 'rgba(27,110,60,0.5)', color: '#1B6E3C' }}
            >
              {busy === 'issue' ? 'Signing…' : 'Affirm and sign Part A'}
            </Button>
          </Box>
        </Box>
      </Collapse>

      {error && <Alert severity="error" sx={{ mb: 1.5, fontSize: 12 }}>{error}</Alert>}

      {!mine.length ? (
        <Typography sx={{ fontSize: 12, color: '#5A6068' }}>
          None issued. Issuing re-verifies the hash first and refuses if it no longer matches.
        </Typography>
      ) : mine.map((c) => (
        <Box key={c.id} sx={{
          p: 1.5, mb: 1, borderRadius: 1.5,
          backgroundColor: '#ECEEF1',
          border: '1px solid #E2E5E9',
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.2, flexWrap: 'wrap' }}>
            <Typography sx={{ fontSize: 12.5, fontFamily: 'monospace', color: '#111315' }}>
              {c.reference}
            </Typography>
            <Chip
              label={c.is_complete ? 'Both parts signed' : 'DRAFT — Part B unsigned'}
              size="small"
              sx={{
                fontSize: 10.5,
                backgroundColor: c.is_complete ? 'rgba(27,110,60,0.15)' : 'rgba(138,97,0,0.15)',
                color: c.is_complete ? '#1B6E3C' : '#8A6100',
              }}
            />
            <Box sx={{ flexGrow: 1 }} />
            <Button
              size="small" disabled={busy === `pdf${c.id}`}
              onClick={() => run(`pdf${c.id}`, () => downloadCertificatePdf(c.id, c.reference))}
              sx={{ fontSize: 11.5, color: '#076E7C' }}
            >
              Download PDF
            </Button>
          </Box>

          {!c.is_complete && canAct && (
            <Box sx={{ mt: 1.2, display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
              {['name', 'designation', 'qualification'].map((field) => (
                <TextField
                  key={field} size="small"
                  placeholder={`Expert ${field}`}
                  value={expert[field]}
                  onChange={(e) => setExpert({ ...expert, [field]: e.target.value })}
                  sx={{
                    flexGrow: 1, minWidth: 130,
                    '& .MuiInputBase-input': { fontSize: 12, color: '#111315' },
                    '& .MuiOutlinedInput-notchedOutline': {
                      borderColor: '#C7CCD2',
                    },
                  }}
                />
              ))}
              <Button
                size="small" variant="outlined" disabled={busy === `sign${c.id}`}
                onClick={() => run(`sign${c.id}`, () => signCertificatePartB(c.id, {
                  part_b_name: expert.name,
                  part_b_designation: expert.designation,
                  part_b_qualification: expert.qualification,
                }))}
                sx={{ fontSize: 11.5, borderColor: 'rgba(138,97,0,0.5)', color: '#8A6100' }}
              >
                Countersign Part B
              </Button>
            </Box>
          )}
        </Box>
      ))}
    </Box>
  );
}

function ExhibitCard({ record, onUpdated, certificates, onCertificatesChanged, canAct }) {
  const [chain, setChain] = useState(null);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  // Falling back to STATUS_STYLE.archived labelled an unrecognised integrity
  // state with the definite word "Archived". Mislabelling an exhibit's
  // integrity is the one thing this page must never do quietly.
  const style = STATUS_STYLE[record.status] ?? {
    label: `Unrecognised status: ${record.status ?? 'none'}`,
    color: '#8A6100',
  };

  const toggle = async () => {
    const next = !open;
    setOpen(next);
    if (next && !chain) setChain(await getCustodyChain(record.id));
  };

  const runVerify = async () => {
    setBusy(true);
    try {
      const result = await verifyEvidence(record.id);
      onUpdated({ ...record, status: result.status });
      setChain(await getCustodyChain(record.id));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box sx={{
      mb: 2, borderRadius: 2, overflow: 'hidden',
      border: '1px solid #E2E5E9',
      backgroundColor: '#F4F5F7',
      borderLeft: `3px solid ${style.color}`,
    }}>
      <Box sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1.5, flexWrap: 'wrap' }}>
          <Typography sx={{ fontSize: 15, fontWeight: 700, color: '#111315',
            fontFamily: 'monospace' }}>
            {record.exhibit_number}
          </Typography>
          <Chip label={style.label} size="small" sx={{
            backgroundColor: `${style.color}22`, color: style.color,
            fontSize: 11, fontWeight: 600,
          }} />
          <Box sx={{ flexGrow: 1 }} />
          {canAct && (
            <Button size="small" variant="outlined" disabled={busy} onClick={runVerify}
              sx={{ fontSize: 11.5, borderColor: 'rgba(7,110,124,0.45)', color: '#076E7C' }}>
              {busy ? 'Verifying…' : 'Re-verify integrity'}
            </Button>
          )}
          <Button size="small" onClick={toggle}
            sx={{ fontSize: 11.5, color: '#5A6068' }}>
            {open ? 'Hide' : 'Show'} chain of custody
          </Button>
        </Box>

        <Typography sx={{ fontSize: 12.5, color: '#5A6068', mb: 1.5 }}>
          {record.original_filename} · {formatBytes(record.file_size_bytes)}
          {record.case_reference ? ` · case ${record.case_reference}` : ''}
        </Typography>

        {/*
          Where the bytes came from. A generated capture and a seized one are
          byte-identical once sealed — same hash, same custody chain, same
          certificate — so the register has to say which it is holding or the
          two are indistinguishable to anyone reading it.
        */}
        <Box sx={{
          mb: 1.5, px: 1.2, py: 0.9, borderRadius: 1.2,
          border: `1px solid ${record.is_demonstration_only ? '#B3261E55' : '#E2E5E9'}`,
          backgroundColor: record.is_demonstration_only
            ? 'rgba(179,38,30,0.10)' : '#F4F5F7',
        }}>
          <Typography sx={{
            fontSize: 11, fontWeight: 700, letterSpacing: 0.5,
            color: record.is_demonstration_only ? '#B3261E' : '#5A6068',
          }}>
            {record.is_demonstration_only
              ? 'SYNTHETIC — GENERATED FOR DEMONSTRATION, NOT EVIDENCE'
              : (record.provenance_label ?? 'Origin not recorded')}
          </Typography>
          {record.provenance_detail && (
            <Typography sx={{ fontSize: 11, color: '#5A6068', mt: 0.3 }}>
              {record.provenance_detail}
            </Typography>
          )}
        </Box>

        <Hash label="SHA-256 (primary)" value={record.sha256_hash} />
        <Hash label="MD5 (Schedule also lists MD5; never relied on alone)" value={record.md5_hash} />

        <CertificatePanel
          record={record}
          certificates={certificates}
          onChanged={onCertificatesChanged}
          canAct={canAct}
        />

        <Collapse in={open}>
          <Box sx={{ mt: 2 }}>
            {chain && (
              <>
                <Alert
                  severity={chain.chain_intact ? 'success' : 'error'}
                  sx={{ mb: 1.5, fontSize: 12.5 }}
                >
                  {chain.chain_intact
                    ? 'Custody chain intact — every entry re-derives from its predecessor.'
                    : `Custody chain BROKEN: ${chain.problems.join('; ')}`}
                </Alert>
                {chain.events.map((e) => (
                  <Box key={e.id} sx={{
                    display: 'flex', gap: 1.5, py: 1,
                    borderBottom: '1px solid #ECEEF1',
                  }}>
                    <Typography sx={{ fontSize: 11.5, color: '#5A6068',
                      minWidth: 26, fontFamily: 'monospace' }}>
                      #{e.sequence}
                    </Typography>
                    <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                      <Typography sx={{ fontSize: 12.5, color: '#111315' }}>
                        {e.action}
                        {e.actor_badge ? ` · badge ${e.actor_badge}` : ''}
                      </Typography>
                      <Typography sx={{ fontSize: 11.5, color: '#5A6068',
                        wordBreak: 'break-all' }}>
                        {e.detail}
                      </Typography>
                      <Typography sx={{ fontSize: 10.5, fontFamily: 'monospace',
                        color: '#5A6068', wordBreak: 'break-all' }}>
                        {new Date(e.timestamp).toLocaleString()} · hash {e.entry_hash?.slice(0, 24)}…
                      </Typography>
                    </Box>
                  </Box>
                ))}
              </>
            )}
          </Box>
        </Collapse>
      </Box>
    </Box>
  );
}

function EvidencePage() {
  // Clearance decides which controls exist at all. An interface that renders
  // a button returning 403 is a fake affordance; the server is the guard, but
  // the officer should not be invited to press something they cannot do.
  const canAct = canActOnEvidence(useCurrentUser());
  const [records, setRecords] = useState([]);
  const [certificates, setCertificates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const refreshCertificates = () =>
    listCertificates()
      .then((d) => setCertificates(unwrap(d)))
      .catch((err) => setError(describeError(err, 'Could not refresh certificates.')));

  useEffect(() => {
    let live = true;
    // Without a catch here a failed request — a 429, a stopped backend —
    // became an unhandled rejection and the page rendered an empty evidence
    // register with no explanation, which reads as "there is no evidence".
    Promise.all([listEvidence(), listCertificates()])
      .then(([e, c]) => {
        if (!live) return;
        setRecords(unwrap(e));
        setCertificates(unwrap(c));
        setError('');
      })
      .catch((err) => { if (live) setError(describeError(err, 'Could not load the evidence register.')); })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, []);

  const replace = (updated) =>
    setRecords((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));

  return (
    <Box sx={{ display: 'flex', backgroundColor: '#FFFFFF', minHeight: '100vh',
      pt: `${BANNER_HEIGHT}px` }}>
      <ClassificationBanner level="restricted" fixed />
      <Sidebar />
      <Box sx={{ flexGrow: 1, minWidth: 0 }}>
        <TopBar />
        <Box sx={{ p: 2.5 }}>
          <Typography sx={{ fontSize: 20, fontWeight: 700, color: '#111315', mb: 0.5 }}>
            Evidence register
          </Typography>
          {/*
            A reading aid, not a translation. BSA/GSJA training assumes a
            Gujarati-medium judicial officer at the taluka-court level, and
            these are the terms they would look for. English stays
            authoritative; see src/i18n/gujarati.js for why the certificate PDF
            is not translated.
          */}
          <Typography lang="gu" sx={{
            fontSize: 13, color: '#5A6068', mb: 0.5,
          }}>
            {GUJARATI.evidenceRegister} · {GUJARATI.act} · {GUJARATI.section}
          </Typography>
          <Typography sx={{ fontSize: 12.5, color: '#5A6068', mb: 2.5 }}>
            Each exhibit is hashed on arrival, before any analysis reads it. The custody log is
            hash-chained, so an altered or removed entry breaks every later link.
            Certificates follow THE SCHEDULE to the Bharatiya Sakshya Adhiniyam 2023,
            referenced by s.63(4)(c).
          </Typography>

          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
              <CircularProgress sx={{ color: '#076E7C' }} />
            </Box>
          ) : !records.length ? (
            <Alert severity="info">
              No exhibits registered yet.
            </Alert>
          ) : (
            records.map((r) => (
              <ExhibitCard
                key={r.id} record={r} onUpdated={replace}
                certificates={certificates}
                onCertificatesChanged={refreshCertificates}
                canAct={canAct}
              />
            ))
          )}
        </Box>
      </Box>
    </Box>
  );
}

export default EvidencePage;
