// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
import { useRef, useState } from 'react';
import { Box, Typography, Button, Alert } from '@mui/material';
import { fileSecondOpinion } from '../../services/forensics';
import { describeError } from '../../services/api';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, RULE, PANEL, PAPER, CYAN, MONO,
} from '../../theme/tokens';

/**
 * File another tool's report beside a sample, and read the two side by side.
 *
 * Everything shown from the report is text from a document written by a program
 * that analysed a hostile package, so it is rendered as text and nothing else: no
 * markup, no links built from it. The server has already bounded every list and
 * string (capture/second_opinion.py).
 *
 * What this page does not do: rank the two, score their agreement, or call
 * MobSF's security score a verdict. It is a hardening measure and the panel says
 * so, because the failure this guards against is an officer reading "73/100" next
 * to a malware tier and taking it for reassurance.
 */
function Row({ row }) {
  return (
    <tr>
      <Box component="td" sx={{ py: 0.7, pr: 1.6, verticalAlign: 'top', color: GREY, width: 170, borderTop: `1px solid ${RULE}`, fontSize: 12 }}>{row.aspect}</Box>
      <Box component="td" sx={{ py: 0.7, pr: 1.6, verticalAlign: 'top', color: INK, borderTop: `1px solid ${RULE}`, fontSize: 12.5 }}>{row.netforensiq}</Box>
      <Box component="td" sx={{ py: 0.7, verticalAlign: 'top', color: INK, borderTop: `1px solid ${RULE}`, fontSize: 12.5 }}>{row.mobsf}</Box>
    </tr>
  );
}

function Result({ result }) {
  const s = result.summary;
  const linked = Boolean(result.exhibit_number);
  return (
    <Box sx={{ mt: 1.6 }}>
      {result.already_filed && (
        <Alert severity="info" sx={{ mb: 1, fontSize: 12.5 }}>
          This exact report was already filed against this sample. It was not filed again, so
          one opinion does not appear as two.
        </Alert>
      )}
      {linked ? (
        <Alert severity="success" sx={{ mb: 1, fontSize: 12.5 }}>
          Filed against exhibit <b>{result.exhibit_number}</b> (the report&apos;s package hash matched
          {result.matched_by === 'examined'
            ? ' the package this system examined' : ' the sealed file'}). A custody entry records it.
        </Alert>
      ) : (
        <Alert severity="warning" sx={{ mb: 1, fontSize: 12.5 }}>{result.unlinked_reason}</Alert>
      )}

      {(s.notes || []).map((n) => (
        <Alert key={n} severity="warning" sx={{ mb: 1, fontSize: 12.5 }}>{n}</Alert>
      ))}

      <Box component="table" sx={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            {['', 'NetForensiq', `MobSF ${s.tool_version || ''}`].map((h) => (
              <Box component="th" key={h} sx={{ textAlign: 'left', py: 0.5, pr: 1.6, fontSize: 11, color: GREY_MUTED, fontWeight: 600, bgcolor: PANEL }}>{h}</Box>
            ))}
          </tr>
        </thead>
        <tbody>{result.comparison.map((row) => <Row key={row.aspect} row={row} />)}</tbody>
      </Box>

      <Typography sx={{ fontSize: 12, color: INK_SOFT, mt: 1.2, borderLeft: `3px solid ${CYAN}`, pl: 1.2 }}>
        {s.score_note}
      </Typography>

      {s.appsec_high.length > 0 && (
        <Box sx={{ mt: 1.2 }}>
          <Typography sx={{ fontSize: 11, color: GREY_MUTED, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            MobSF high-severity findings ({s.appsec_counts.high})
          </Typography>
          <Box component="ul" sx={{ m: 0, pl: 2.2 }}>
            {s.appsec_high.map((t) => (
              <Typography component="li" key={t} sx={{ fontSize: 12, color: INK_SOFT }}>{t}</Typography>
            ))}
          </Box>
        </Box>
      )}
      {s.apkid.length > 0 && (
        <Box sx={{ mt: 1.2 }}>
          <Typography sx={{ fontSize: 11, color: GREY_MUTED, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Packers, obfuscators and evasion MobSF identified (APKiD)
          </Typography>
          <Box component="ul" sx={{ m: 0, pl: 2.2 }}>
            {s.apkid.map((t) => (
              <Typography component="li" key={t} sx={{ fontSize: 11.5, color: INK_SOFT, fontFamily: MONO }}>{t}</Typography>
            ))}
          </Box>
        </Box>
      )}
      <Typography sx={{ fontSize: 11, color: GREY_MUTED, mt: 1.4, fontFamily: MONO, wordBreak: 'break-all' }}>
        report sha256 {result.report_sha256}<br />describes package sha256 {result.subject_sha256}
      </Typography>
      <Typography sx={{ fontSize: 11.5, color: GREY, mt: 0.6 }}>
        An opinion produced elsewhere, kept as received. It is not evidence and not this
        system&apos;s finding.
      </Typography>
    </Box>
  );
}

function SecondOpinion() {
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  const submit = async () => {
    setBusy(true);
    setError('');
    try {
      setResult(await fileSecondOpinion(file));
    } catch (err) {
      setError(describeError(err, 'The report could not be filed.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box sx={{ border: `1px solid ${RULE}`, bgcolor: PAPER, mb: 2 }}>
      <Box sx={{ px: 1.8, py: 1.1, borderBottom: `1px solid ${RULE}`, bgcolor: PANEL }}>
        <Typography sx={{ fontSize: 12.5, fontWeight: 700, color: INK }}>Second opinion</Typography>
        <Typography sx={{ fontSize: 11, color: GREY_MUTED, mt: 0.2 }}>
          File a MobSF report beside this sample. Run MobSF yourself and download its JSON report;
          nothing here runs it.
        </Typography>
      </Box>
      <Box sx={{ px: 1.8, py: 1.4 }}>
        <Box sx={{ display: 'flex', gap: 1.2, alignItems: 'center', flexWrap: 'wrap' }}>
          <Button variant="outlined" size="small" onClick={() => inputRef.current?.click()}
            sx={{ textTransform: 'none', color: INK, borderColor: RULE }}>
            {file ? file.name : 'Choose the MobSF JSON report'}
          </Button>
          <input
            ref={inputRef} type="file" accept=".json,application/json" hidden
            onChange={(e) => { setFile(e.target.files?.[0] ?? null); setResult(null); setError(''); }}
          />
          <Button variant="contained" disableElevation size="small" onClick={submit}
            disabled={!file || busy}
            sx={{ bgcolor: INK, color: PAPER, textTransform: 'none', '&:hover': { bgcolor: INK_SOFT } }}>
            {busy ? 'Filing…' : 'File beside this sample'}
          </Button>
        </Box>
        {error && <Alert severity="error" sx={{ mt: 1.2, fontSize: 12.5 }}>{error}</Alert>}
        {result && <Result result={result} />}
      </Box>
    </Box>
  );
}

export default SecondOpinion;
