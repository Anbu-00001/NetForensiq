import { useEffect, useState } from 'react';
import {
  Box, Typography, Chip, Button, CircularProgress, Alert, Collapse,
} from '@mui/material';
import Sidebar from '../components/layout/Sidebar';
import TopBar from '../components/layout/TopBar';
import {
  listEvidence, getCustodyChain, verifyEvidence, unwrap, formatBytes,
} from '../services/forensics';

const STATUS_STYLE = {
  sealed: { color: '#00E68A', label: 'Sealed — hash verified' },
  tampered: { color: '#FF3B5C', label: 'INTEGRITY FAILED' },
  archived: { color: '#7A8699', label: 'Archived' },
};

function Hash({ label, value }) {
  return (
    <Box sx={{ mb: 0.8 }}>
      <Typography sx={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.6,
        color: 'rgba(229,231,235,0.4)' }}>
        {label}
      </Typography>
      <Typography sx={{ fontSize: 11.5, fontFamily: 'monospace', color: '#E5E7EB',
        wordBreak: 'break-all' }}>
        {value || '—'}
      </Typography>
    </Box>
  );
}

function ExhibitCard({ record, onUpdated }) {
  const [chain, setChain] = useState(null);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const style = STATUS_STYLE[record.status] ?? STATUS_STYLE.archived;

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
      border: '1px solid rgba(255,255,255,0.07)',
      backgroundColor: 'rgba(255,255,255,0.02)',
      borderLeft: `3px solid ${style.color}`,
    }}>
      <Box sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1.5, flexWrap: 'wrap' }}>
          <Typography sx={{ fontSize: 15, fontWeight: 700, color: '#E5E7EB',
            fontFamily: 'monospace' }}>
            {record.exhibit_number}
          </Typography>
          <Chip label={style.label} size="small" sx={{
            backgroundColor: `${style.color}22`, color: style.color,
            fontSize: 11, fontWeight: 600,
          }} />
          <Box sx={{ flexGrow: 1 }} />
          <Button size="small" variant="outlined" disabled={busy} onClick={runVerify}
            sx={{ fontSize: 11.5, borderColor: 'rgba(0,212,255,0.4)', color: '#00D4FF' }}>
            {busy ? 'Verifying…' : 'Re-verify integrity'}
          </Button>
          <Button size="small" onClick={toggle}
            sx={{ fontSize: 11.5, color: 'rgba(229,231,235,0.6)' }}>
            {open ? 'Hide' : 'Show'} chain of custody
          </Button>
        </Box>

        <Typography sx={{ fontSize: 12.5, color: 'rgba(229,231,235,0.55)', mb: 1.5 }}>
          {record.original_filename} · {formatBytes(record.file_size_bytes)}
          {record.case_reference ? ` · case ${record.case_reference}` : ''}
        </Typography>

        <Hash label="SHA-256 (primary)" value={record.sha256_hash} />
        <Hash label="MD5 (Schedule also lists MD5; never relied on alone)" value={record.md5_hash} />

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
                    borderBottom: '1px solid rgba(255,255,255,0.05)',
                  }}>
                    <Typography sx={{ fontSize: 11.5, color: 'rgba(229,231,235,0.35)',
                      minWidth: 26, fontFamily: 'monospace' }}>
                      #{e.sequence}
                    </Typography>
                    <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                      <Typography sx={{ fontSize: 12.5, color: '#E5E7EB' }}>
                        {e.action}
                        {e.actor_badge ? ` · badge ${e.actor_badge}` : ''}
                      </Typography>
                      <Typography sx={{ fontSize: 11.5, color: 'rgba(229,231,235,0.5)',
                        wordBreak: 'break-all' }}>
                        {e.detail}
                      </Typography>
                      <Typography sx={{ fontSize: 10.5, fontFamily: 'monospace',
                        color: 'rgba(229,231,235,0.3)', wordBreak: 'break-all' }}>
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
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listEvidence()
      .then((d) => setRecords(unwrap(d)))
      .finally(() => setLoading(false));
  }, []);

  const replace = (updated) =>
    setRecords((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));

  return (
    <Box sx={{ display: 'flex', backgroundColor: '#080B14', minHeight: '100vh' }}>
      <Sidebar />
      <Box sx={{ flexGrow: 1, minWidth: 0 }}>
        <TopBar />
        <Box sx={{ p: 2.5 }}>
          <Typography sx={{ fontSize: 20, fontWeight: 700, color: '#E5E7EB', mb: 0.5 }}>
            Evidence register
          </Typography>
          <Typography sx={{ fontSize: 12.5, color: 'rgba(229,231,235,0.45)', mb: 2.5 }}>
            Each exhibit is hashed on arrival, before any analysis reads it. The custody log is
            hash-chained, so an altered or removed entry breaks every later link.
            Certificates follow THE SCHEDULE to the Bharatiya Sakshya Adhiniyam 2023,
            referenced by s.63(4)(c).
          </Typography>

          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
              <CircularProgress sx={{ color: '#00D4FF' }} />
            </Box>
          ) : !records.length ? (
            <Alert severity="info">
              No exhibits registered yet.
            </Alert>
          ) : (
            records.map((r) => (
              <ExhibitCard key={r.id} record={r} onUpdated={replace} />
            ))
          )}
        </Box>
      </Box>
    </Box>
  );
}

export default EvidencePage;
