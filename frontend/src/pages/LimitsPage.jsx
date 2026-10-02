// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
import { useEffect, useState } from 'react';
import { Box, Typography, Alert, CircularProgress, Link } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import Sidebar from '../components/layout/Sidebar';
import TopBar from '../components/layout/TopBar';
import ClassificationBanner, { BANNER_HEIGHT } from '../components/layout/ClassificationBanner';
import { getEngineLimits } from '../services/engine';
import { isAuthenticated } from '../services/auth';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, RULE, RULE_STRONG, PANEL, PANEL_ALT, PAPER, CYAN, MONO,
} from '../theme/tokens';

/**
 * What this tool cannot establish.
 *
 * Every figure on this page is read from the API, which reads it from the measured
 * validation data and from the code. Nothing here is typed, because the last
 * version of this information — in the investigation report — said "thirty-five
 * thresholds" and "ten rules" long after both had changed.
 *
 * Public, with the plain shell when nobody is signed in: the page that says what
 * not to rely on should be readable before an account exists. The page makes no
 * claim of compliance with any standard; it says what the standards describe and
 * where this tool stops.
 */
function Panel({ title, subtitle, children }) {
  return (
    <Box sx={{ border: `1px solid ${RULE}`, bgcolor: PAPER, mb: 2 }}>
      <Box sx={{ px: 1.8, py: 1.1, borderBottom: `1px solid ${RULE}`, bgcolor: PANEL }}>
        <Typography component="h2" sx={{ fontSize: 13, fontWeight: 700, color: INK }}>{title}</Typography>
        {subtitle && <Typography sx={{ fontSize: 11.5, color: GREY_MUTED, mt: 0.2 }}>{subtitle}</Typography>}
      </Box>
      <Box sx={{ px: 1.8, py: 1.4 }}>{children}</Box>
    </Box>
  );
}

const pct = (x, places = 0) => `${(x * 100).toFixed(places)}%`;

function Figures({ validation: v, network: n }) {
  if (!v) {
    return (
      <Alert severity="warning" sx={{ fontSize: 12.5 }}>
        No validation figures are installed on this system, so nothing is claimed about how often
        this engine is wrong.
      </Alert>
    );
  }
  const u = v.apk.unseen;
  const l = v.apk.legitimate;
  const rows = [
    ['Malware it had not seen', `${u.detected} of ${u.n} reached a tier (${pct(u.detected / u.n)}; 95% interval ${pct(u.ci95[0])}–${pct(u.ci95[1])})`,
      `${u.missed} reached none (${pct(u.missed / u.n)}); ${u.could_not_be_examined} could not be examined`],
    ['Legitimate apps', `${l.false_positives} of ${l.examined} examined reached a tier (95% upper bound ${pct(l.upper95, 1)})`,
      `${l.could_not_be_examined} of ${l.n} could not be examined and are not counted as clean`],
    ['Malware it was built from', `${v.apk.in_sample.detected} of ${v.apk.in_sample.n}`,
      'In-sample: shown only to be compared with the first row. Do not quote it.'],
    ['Network rules', `${n.ordinary_captures} captures of ordinary traffic, ${n.attack_captures} of attacks`,
      `${n.rules_firing_on_ordinary_traffic.length} rules fired on ordinary traffic; ${n.rules_untested.length} have fired on nothing and are untested`],
  ];
  return (
    <Box component="table" sx={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
      <tbody>
        {rows.map(([what, result, note]) => (
          <tr key={what}>
            <Box component="td" sx={{ py: 0.8, pr: 2, verticalAlign: 'top', color: GREY, width: 190, borderTop: `1px solid ${RULE}` }}>{what}</Box>
            <Box component="td" sx={{ py: 0.8, pr: 2, verticalAlign: 'top', color: INK, fontWeight: 600, borderTop: `1px solid ${RULE}` }}>{result}</Box>
            <Box component="td" sx={{ py: 0.8, verticalAlign: 'top', color: INK_SOFT, borderTop: `1px solid ${RULE}` }}>{note}</Box>
          </tr>
        ))}
      </tbody>
    </Box>
  );
}

function Quote({ text, where }) {
  return (
    <Box sx={{ borderLeft: `3px solid ${RULE_STRONG}`, pl: 1.4, my: 1 }}>
      <Typography sx={{ fontSize: 12.5, color: INK_SOFT, fontStyle: 'italic' }}>“{text}”</Typography>
      <Typography sx={{ fontSize: 11, color: GREY_MUTED }}>{where}</Typography>
    </Box>
  );
}

function Standard({ standard: s }) {
  return (
    <Panel
      title={`${s.id} — ${s.title}`}
      subtitle={`${s.authors ? `${s.authors} · ` : ''}${s.date}${s.status ? ` · ${s.status}` : ''} · ${s.verified ? 'text read' : 'secondary source: text not read'}`}
    >
      <Typography sx={{ fontSize: 12, color: GREY, mb: 0.6 }}>{s.note}</Typography>
      {s.quotes.map((q) => <Quote key={q.where} text={q.text} where={q.where} />)}
      <Box component="table" sx={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5, mt: 1.4 }}>
        <thead>
          <tr>
            {['Stage', 'What this tool does', 'What it does not do'].map((h) => (
              <Box component="th" key={h} sx={{ textAlign: 'left', py: 0.6, pr: 1.6, color: GREY_MUTED, fontWeight: 600, bgcolor: PANEL_ALT }}>{h}</Box>
            ))}
          </tr>
        </thead>
        <tbody>
          {s.mapping.map((m) => (
            <tr key={m.phase}>
              <Box component="td" sx={{ py: 0.8, pr: 1.6, verticalAlign: 'top', fontWeight: 700, color: INK, width: 120, borderTop: `1px solid ${RULE}` }}>{m.phase}</Box>
              <Box component="td" sx={{ py: 0.8, pr: 1.6, verticalAlign: 'top', color: INK_SOFT, borderTop: `1px solid ${RULE}` }}>{m.does}</Box>
              <Box component="td" sx={{ py: 0.8, verticalAlign: 'top', color: INK_SOFT, borderTop: `1px solid ${RULE}` }}>{m.does_not}</Box>
            </tr>
          ))}
        </tbody>
      </Box>
      <Link href={s.url} target="_blank" rel="noreferrer" sx={{ fontSize: 11.5, color: CYAN, display: 'inline-block', mt: 1 }}>
        {s.url}
      </Link>
    </Panel>
  );
}

function Content({ doc }) {
  return (
    <>
      <Typography component="h1" sx={{ fontSize: 20, fontWeight: 700, color: INK }}>
        Limits of this tool
      </Typography>
      <Typography sx={{ fontSize: 12.5, color: INK_SOFT, mt: 0.6, mb: 2.4, maxWidth: 820 }}>
        What it cannot establish, with the measured figures behind each limit. Every number here
        is read from the validation data or from the code, not typed.
      </Typography>

      <Alert severity="info" sx={{ mb: 2, fontSize: 12.5 }}>{doc.status}</Alert>

      <Panel title="If the tool finds nothing" subtitle="Say this, not “clean” or “safe”.">
        <Box sx={{ display: 'grid', gap: 1.6, gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' } }}>
          <Box>
            <Typography sx={{ fontSize: 11, color: GREY_MUTED, textTransform: 'uppercase', letterSpacing: 0.5 }}>
              An Android sample reaches tier 1
            </Typography>
            <Typography sx={{ fontSize: 13, color: INK, mt: 0.4 }}>{doc.nothing_found.apk}</Typography>
          </Box>
          <Box>
            <Typography sx={{ fontSize: 11, color: GREY_MUTED, textTransform: 'uppercase', letterSpacing: 0.5 }}>
              A capture raises no finding
            </Typography>
            <Typography sx={{ fontSize: 13, color: INK, mt: 0.4 }}>{doc.nothing_found.network}</Typography>
          </Box>
        </Box>
      </Panel>

      <Panel title="What was measured" subtitle="Intervals are exact (Clopper–Pearson). Full method: validation/VALIDATION_REPORT.md.">
        <Figures validation={doc.validation} network={doc.network} />
      </Panel>

      <Panel title="What it cannot establish">
        <Box component="ul" sx={{ m: 0, pl: 2.2 }}>
          {doc.cannot.map((line) => (
            <Typography component="li" key={line} sx={{ fontSize: 12.5, color: INK_SOFT, mb: 0.7 }}>{line}</Typography>
          ))}
        </Box>
      </Panel>

      <Typography component="h2" sx={{ fontSize: 14, fontWeight: 700, color: INK, mt: 3, mb: 1 }}>
        Against the standards
      </Typography>
      <Typography sx={{ fontSize: 12, color: GREY, mb: 1.4, maxWidth: 820 }}>
        These describe what forensic work involves. Nothing below says this tool complies with
        them, and neither standard says anything about this tool.
      </Typography>
      {doc.standards.map((s) => <Standard key={s.id} standard={s} />)}

      <Panel title={`Every source this interface cites (${doc.references.length})`}
             subtitle="Printed as text, so a printed page still names them. “secondary” means only a secondary account was read.">
        <Box component="ul" sx={{ m: 0, pl: 2.2 }}>
          {doc.references.map((r) => (
            <Typography component="li" key={r.url} sx={{ fontSize: 11.5, color: INK_SOFT, mb: 0.5 }}>
              {r.title} — {r.publisher}, {r.date}
              {!r.verified ? ' (secondary)' : ''}
              <Box component="span" sx={{ display: 'block', fontFamily: MONO, fontSize: 10.5, color: GREY_MUTED, wordBreak: 'break-all' }}>
                {r.url}
              </Box>
            </Typography>
          ))}
        </Box>
      </Panel>
    </>
  );
}

function LimitsPage() {
  const [doc, setDoc] = useState(null);
  const [error, setError] = useState('');
  const signedIn = isAuthenticated();

  useEffect(() => {
    let live = true;
    getEngineLimits()
      .then((d) => { if (live) setDoc(d); })
      .catch(() => { if (live) setError('The limits could not be loaded from this system.'); });
    return () => { live = false; };
  }, []);

  const body = error
    ? <Alert severity="error">{error}</Alert>
    : doc ? <Content doc={doc} /> : <CircularProgress size={22} />;

  if (signedIn) {
    return (
      <Box sx={{ display: 'flex', bgcolor: PANEL, minHeight: '100vh', pt: `${BANNER_HEIGHT}px` }}>
        <ClassificationBanner fixed />
        <Sidebar />
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <TopBar />
          <Box sx={{ p: 3, maxWidth: 1100 }}>{body}</Box>
        </Box>
      </Box>
    );
  }
  return (
    <Box sx={{ minHeight: '100vh', bgcolor: PANEL }}>
      <ClassificationBanner level="unclassified" />
      <Box sx={{ p: 3, maxWidth: 1100, mx: 'auto' }}>
        <Link component={RouterLink} to="/" sx={{ fontSize: 12, color: CYAN, display: 'inline-block', mb: 2 }}>
          ← NetForensiq
        </Link>
        {body}
      </Box>
    </Box>
  );
}

export default LimitsPage;
