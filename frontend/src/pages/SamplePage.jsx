import { useRef, useState } from 'react';
import {
  Box, Typography, Button, TextField, Alert, LinearProgress, MenuItem,
} from '@mui/material';
import ScienceOutlinedIcon from '@mui/icons-material/ScienceOutlined';
import Sidebar from '../components/layout/Sidebar';
import TopBar from '../components/layout/TopBar';
import ClassificationBanner from '../components/layout/ClassificationBanner';
import { examineSample } from '../services/forensics';
import { useCurrentUser } from '../services/session';
import { describeError } from '../services/api';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, RULE, RULE_STRONG, PANEL, PANEL_ALT, PAPER,
  CYAN, CRITICAL, HIGH, MEDIUM, INTACT, LOW, MONO,
} from '../theme/tokens';

/**
 * Examining a submitted Android package.
 *
 * Why this screen shows its working
 * ---------------------------------
 * The easy version of this feature is a red banner that says MALICIOUS. That
 * is also the useless version: an officer cannot put it in a case diary, an
 * examiner cannot check it, and defence counsel dismantles it in one question
 * — "on what basis?".
 *
 * So the layout is built around answering that question before it is asked.
 * The score is never shown without the observations that produced it. Each
 * classification names the capabilities that qualified the sample for it. And
 * anything found in the code that the manifest does not corroborate is listed
 * separately, marked as not scoring, because almost every APK statically links
 * libraries that mention AccessibilityService without ever using it.
 *
 * The correlation panel is the part no standalone scanner can produce: an
 * indicator inside the file that also appears in a sealed capture already held
 * as evidence. That turns a capability into an event with a timestamp.
 */

const ORIGINS = [
  {
    value: 'seized',
    label: 'Seized — recovered from a device or account under investigation',
    help: 'Evidence. This is a declaration you are making at intake and it is '
        + 'written into the chain of custody.',
    tone: CRITICAL,
  },
  {
    value: 'reference',
    label: 'Reference — a known sample from a published corpus',
    help: 'A real sample, but not evidence in any case.',
    tone: MEDIUM,
  },
  {
    value: 'synthetic',
    label: 'Synthetic — built for testing or demonstration',
    help: 'Not evidence and never presentable as evidence.',
    tone: LOW,
  },
];

const VERDICT_TONE = {
  'highly suspicious': CRITICAL,
  suspicious: HIGH,
  elevated: MEDIUM,
  low: INTACT,
  indeterminate: GREY,
};

function Label({ children }) {
  return (
    <Typography sx={{
      fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.7,
      color: GREY_MUTED, mb: 0.6, fontWeight: 600,
    }}>
      {children}
    </Typography>
  );
}

function Meter({ score }) {
  // The bar is a reading aid, not the finding. It is drawn next to the number
  // and the number next to its reasons, so nothing here can be quoted alone.
  const tone = score >= 70 ? CRITICAL : score >= 40 ? HIGH : score >= 15 ? MEDIUM : INTACT;
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
      <Typography sx={{ fontFamily: MONO, fontSize: 30, color: tone, lineHeight: 1 }}>
        {score}
      </Typography>
      <Box sx={{ flex: 1, minWidth: 120 }}>
        <Box sx={{ height: 8, bgcolor: PANEL_ALT, borderRadius: 0.5, overflow: 'hidden' }}>
          <Box sx={{ width: `${Math.min(score, 100)}%`, height: '100%', bgcolor: tone }} />
        </Box>
        <Typography sx={{ fontSize: 10.5, color: GREY_MUTED, mt: 0.4 }}>
          out of 100 — additive, from the observations listed below
        </Typography>
      </Box>
    </Box>
  );
}

function Chip({ children, tone = GREY, title }) {
  return (
    <Box
      title={title}
      component="span"
      sx={{
        display: 'inline-block', px: 0.8, py: 0.25, mr: 0.6, mb: 0.6,
        border: `1px solid ${tone}`, color: tone, fontFamily: MONO,
        fontSize: 10.5, borderRadius: 0.4, whiteSpace: 'nowrap',
      }}
    >
      {children}
    </Box>
  );
}

function Panel({ title, subtitle, children }) {
  return (
    <Box sx={{ border: `1px solid ${RULE}`, bgcolor: PAPER, mb: 2 }}>
      <Box sx={{ px: 1.8, py: 1.1, borderBottom: `1px solid ${RULE}`, bgcolor: PANEL }}>
        <Typography sx={{ fontSize: 12.5, fontWeight: 700, color: INK }}>{title}</Typography>
        {subtitle && (
          <Typography sx={{ fontSize: 11, color: GREY_MUTED, mt: 0.2 }}>{subtitle}</Typography>
        )}
      </Box>
      <Box sx={{ px: 1.8, py: 1.4 }}>{children}</Box>
    </Box>
  );
}

function FamilyCard({ family }) {
  const pct = Math.round(family.confidence * 100);
  return (
    <Box sx={{ border: `1px solid ${RULE_STRONG}`, p: 1.4, mb: 1.2, bgcolor: PANEL_ALT }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 2, alignItems: 'baseline' }}>
        <Typography sx={{ fontSize: 14, fontWeight: 700, color: CRITICAL }}>
          {family.family}
        </Typography>
        <Typography sx={{ fontFamily: MONO, fontSize: 12, color: INK_SOFT, whiteSpace: 'nowrap' }}>
          {pct}% confidence
        </Typography>
      </Box>
      <Typography sx={{ fontSize: 12, color: INK_SOFT, mt: 0.5 }}>
        {family.description}
      </Typography>
      <Typography sx={{ fontSize: 11.5, color: INK, mt: 0.8, fontStyle: 'italic' }}>
        {family.investigative_note}
      </Typography>
      <Box sx={{ mt: 1 }}>
        <Label>Capabilities that qualified it</Label>
        {family.required_signals.map((s) => <Chip key={s} tone={CRITICAL}>{s}</Chip>)}
      </Box>
      {family.supporting_signals?.length > 0 && (
        <Box sx={{ mt: 0.8 }}>
          <Label>Consistent with, but not exclusive to, this family</Label>
          {family.supporting_signals.map((s) => <Chip key={s} tone={MEDIUM}>{s}</Chip>)}
        </Box>
      )}
    </Box>
  );
}

export default function SamplePage() {
  const user = useCurrentUser();
  const allowed = ['admin', 'expert'].includes(user?.role);

  const [file, setFile] = useState(null);
  const [origin, setOrigin] = useState('');
  const [meta, setMeta] = useState({
    case_reference: '', fir_number: '', police_station: '', seized_from: '',
    acquisition_notes: '', archive_password: '',
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [report, setReport] = useState(null);
  const inputRef = useRef(null);

  const chosenOrigin = ORIGINS.find((o) => o.value === origin);

  const submit = async () => {
    if (!file || !origin) return;
    setBusy(true); setError(''); setReport(null);
    try {
      const form = new FormData();
      form.append('file', file);
      form.append('provenance', origin);
      Object.entries(meta).forEach(([k, v]) => v && form.append(k, v));
      setReport(await examineSample(form));
    } catch (e) {
      setError(describeError(e) ?? 'The examination failed before it completed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box sx={{ display: 'flex', bgcolor: PANEL, minHeight: '100vh' }}>
      <ClassificationBanner />
      <Sidebar />
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <TopBar />
        <Box sx={{ p: 3, maxWidth: 1100 }}>
          <Typography sx={{ fontSize: 20, fontWeight: 700, color: INK }}>
            Examine a submitted sample
          </Typography>
          <Typography sx={{ fontSize: 12.5, color: INK_SOFT, mt: 0.6, mb: 2.4, maxWidth: 780 }}>
            The package is sealed and hashed before anything opens it, and the
            examination runs against the sealed copy. Analysis is entirely
            static — the sample is never executed — and every conclusion below
            is shown with the observation that produced it.
          </Typography>

          {!allowed && (
            <Alert severity="warning" sx={{ mb: 2 }}>
              Submitting a sample requires Commander/Administrator or FSL Examiner
              clearance. You can read a completed examination, but not start one.
            </Alert>
          )}

          <Panel
            title="Take the sample into evidence"
            subtitle="An .apk, or a .zip containing one — a single archive layer is opened for you, so no hostile file has to be extracted by hand."
          >
            <Box
              onClick={() => allowed && inputRef.current?.click()}
              sx={{
                border: `1px dashed ${RULE_STRONG}`, p: 3, textAlign: 'center',
                cursor: allowed ? 'pointer' : 'not-allowed', bgcolor: PANEL_ALT, mb: 2,
              }}
            >
              <ScienceOutlinedIcon sx={{ color: GREY, fontSize: 26 }} />
              <Typography sx={{ fontSize: 13.5, fontWeight: 700, color: INK, mt: 0.6 }}>
                {file ? file.name : 'Drop an .apk or .zip here, or click to choose'}
              </Typography>
              <Typography sx={{ fontSize: 11.5, color: GREY_MUTED, mt: 0.3 }}>
                {file
                  ? `${(file.size / 1e6).toFixed(1)} MB — checked by magic number, not extension`
                  : 'Up to 256 MB'}
              </Typography>
              <input
                ref={inputRef} type="file" accept=".apk,.zip" hidden
                onChange={(e) => { setFile(e.target.files?.[0] ?? null); setReport(null); }}
              />
            </Box>

            <Label>Where this sample came from — required</Label>
            <TextField
              select fullWidth size="small" value={origin} disabled={!allowed}
              onChange={(e) => setOrigin(e.target.value)}
              sx={{ mb: 0.6, bgcolor: PAPER }}
            >
              {ORIGINS.map((o) => (
                <MenuItem key={o.value} value={o.value} sx={{ fontSize: 13 }}>
                  {o.label}
                </MenuItem>
              ))}
            </TextField>
            <Typography sx={{
              fontSize: 11.5, mb: 2,
              color: chosenOrigin ? chosenOrigin.tone : GREY_MUTED,
              fontWeight: chosenOrigin ? 600 : 400,
            }}>
              {chosenOrigin
                ? chosenOrigin.help
                : 'There is no default. The system will not decide on your behalf what this file is.'}
            </Typography>

            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2, mb: 2 }}>
              {[
                ['case_reference', 'Case reference'],
                ['fir_number', 'FIR number'],
                ['police_station', 'Police station'],
                ['seized_from', 'Recovered from'],
              ].map(([key, label]) => (
                <Box key={key}>
                  <Label>{label}</Label>
                  <TextField
                    fullWidth size="small" value={meta[key]} disabled={!allowed}
                    onChange={(e) => setMeta({ ...meta, [key]: e.target.value })}
                    sx={{ bgcolor: PAPER }}
                  />
                </Box>
              ))}
            </Box>

            <Label>Archive password — only if the .zip is encrypted</Label>
            <TextField
              fullWidth size="small" value={meta.archive_password} disabled={!allowed}
              onChange={(e) => setMeta({ ...meta, archive_password: e.target.value })}
              placeholder="Leave blank unless the archive asks for one"
              sx={{ bgcolor: PAPER, mb: 0.6 }}
            />
            <Typography sx={{ fontSize: 11, color: GREY_MUTED, mb: 2 }}>
              Samples are routinely distributed password-protected so that mail
              gateways cannot open them. <strong>infected</strong>, malware, virus,
              sample and password are tried automatically, so this is usually
              only needed for an unusual one.
            </Typography>

            <Label>Acquisition notes</Label>
            <TextField
              fullWidth size="small" multiline minRows={2} value={meta.acquisition_notes}
              disabled={!allowed}
              onChange={(e) => setMeta({ ...meta, acquisition_notes: e.target.value })}
              sx={{ bgcolor: PAPER, mb: 0.6 }}
            />
            <Typography sx={{ fontSize: 11, color: GREY_MUTED, mb: 2 }}>
              How it was obtained, from whom, by whom. Written into the chain of
              custody and not editable afterwards.
            </Typography>

            {busy && <LinearProgress sx={{ mb: 1.5 }} />}
            {error && <Alert severity="error" sx={{ mb: 1.5 }}>{error}</Alert>}

            <Button
              variant="contained" disableElevation onClick={submit}
              disabled={!allowed || !file || !origin || busy}
              sx={{
                bgcolor: INK, color: PAPER, textTransform: 'none', fontWeight: 700,
                px: 3, '&:hover': { bgcolor: INK_SOFT },
              }}
            >
              {busy ? 'Sealing and examining…' : 'Seal and examine'}
            </Button>
          </Panel>

          {report && (
            <>
              <Panel
                title="Assessment"
                subtitle={`Exhibit ${report.exhibit_number} — ${report.provenance_label}`}
              >
                <Box sx={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'flex-start' }}>
                  <Box sx={{ minWidth: 260, flex: 1 }}>
                    <Meter score={report.score} />
                    <Typography sx={{
                      fontSize: 15, fontWeight: 700, mt: 1,
                      color: VERDICT_TONE[report.verdict] ?? GREY,
                      textTransform: 'uppercase', letterSpacing: 0.5,
                    }}>
                      {report.verdict}
                    </Typography>
                    <Typography sx={{ fontSize: 12, color: INK_SOFT, mt: 0.4 }}>
                      {report.verdict_reason}
                    </Typography>
                  </Box>
                  <Box sx={{ minWidth: 280, flex: 1 }}>
                    <Label>Package</Label>
                    <Typography sx={{ fontFamily: MONO, fontSize: 12.5, color: INK, mb: 0.8 }}>
                      {report.package || '— manifest unreadable —'}
                      {report.version_name ? `  v${report.version_name}` : ''}
                    </Typography>
                    <Label>SHA-256 of the sealed exhibit</Label>
                    <Typography sx={{
                      fontFamily: MONO, fontSize: 10.5, color: INK, wordBreak: 'break-all', mb: 0.8,
                    }}>
                      {report.sealed_sha256}
                    </Typography>
                    <Typography sx={{ fontSize: 11, color: GREY_MUTED }}>
                      minSdk {report.min_sdk || '?'} · targetSdk {report.target_sdk || '?'} ·{' '}
                      {report.files?.dex ?? 0} dex · {report.files?.total ?? 0} entries
                      {report.debuggable ? ' · debuggable' : ''}
                      {report.unwrapped_from ? ` · unwrapped from ${report.unwrapped_from}` : ''}
                    </Typography>
                  </Box>
                </Box>
                {report.errors?.length > 0 && (
                  <Alert severity="info" sx={{ mt: 1.5, fontSize: 12 }}>
                    {report.errors.join(' · ')}
                  </Alert>
                )}
              </Panel>

              <Panel
                title="What this behaves like"
                subtitle="Assigned only when every capability the family mechanically requires is present."
              >
                {report.families?.length > 0 ? (
                  report.families.map((f) => <FamilyCard key={f.family} family={f} />)
                ) : (
                  <Typography sx={{ fontSize: 12.5, color: INK_SOFT }}>
                    No family in the model matched. That is a real answer, not a
                    clean bill of health — this model describes six behaviours,
                    and a sample can be harmful in a way none of them covers.
                  </Typography>
                )}
              </Panel>

              {report.correlation && (
                <Panel
                  title="Seen on the network"
                  subtitle={`${report.correlation.checked_domains} names and ${report.correlation.checked_ips} addresses from inside this package, checked against captures already in evidence.`}
                >
                  {(report.correlation.matches?.length > 0
                    || report.correlation.feed_matches?.length > 0) ? (
                    <>
                      {report.correlation.matches?.map((m, i) => (
                        <Box key={`m${i}`} sx={{
                          borderLeft: `3px solid ${CRITICAL}`, pl: 1.2, py: 0.7, mb: 0.8,
                          bgcolor: PANEL_ALT,
                        }}>
                          <Typography sx={{ fontFamily: MONO, fontSize: 12.5, color: CRITICAL }}>
                            {m.indicator}
                          </Typography>
                          <Typography sx={{ fontSize: 11.5, color: INK_SOFT }}>
                            {m.detail} · {m.kind === 'dns' ? 'resolved' : 'contacted'} in{' '}
                            {m.session_name}{m.exhibit ? ` (exhibit ${m.exhibit})` : ''}
                            {m.at ? ` · ${m.at}` : ''}
                          </Typography>
                        </Box>
                      ))}
                      {report.correlation.feed_matches?.map((m, i) => (
                        <Box key={`f${i}`} sx={{
                          borderLeft: `3px solid ${HIGH}`, pl: 1.2, py: 0.7, mb: 0.8,
                        }}>
                          <Typography sx={{ fontFamily: MONO, fontSize: 12.5, color: HIGH }}>
                            {m.indicator}
                          </Typography>
                          <Typography sx={{ fontSize: 11.5, color: INK_SOFT }}>{m.detail}</Typography>
                        </Box>
                      ))}
                    </>
                  ) : (
                    <Typography sx={{ fontSize: 12.5, color: INK_SOFT }}>
                      None of this package&apos;s endpoints appear in any capture
                      currently held. That does not clear the sample — it means
                      the traffic it would generate has not been captured here.
                    </Typography>
                  )}
                </Panel>
              )}

              <Panel
                title="Permissions it asks for"
                subtitle="Only those that carry weight are listed; the score contribution of each is shown."
              >
                {report.permission_findings?.length > 0 ? (
                  report.permission_findings.map((p) => (
                    <Box key={p.permission} sx={{
                      display: 'flex', gap: 1.5, py: 0.6,
                      borderBottom: `1px solid ${RULE}`,
                    }}>
                      <Typography sx={{
                        fontFamily: MONO, fontSize: 11.5, minWidth: 26,
                        color: p.weight >= 8 ? CRITICAL : p.weight >= 5 ? HIGH : MEDIUM,
                        fontWeight: 700,
                      }}>
                        +{p.weight}
                      </Typography>
                      <Box>
                        <Typography sx={{ fontFamily: MONO, fontSize: 11.5, color: INK }}>
                          {p.permission.replace('android.permission.', '')}
                        </Typography>
                        <Typography sx={{ fontSize: 11.5, color: INK_SOFT }}>{p.why}</Typography>
                      </Box>
                    </Box>
                  ))
                ) : (
                  <Typography sx={{ fontSize: 12.5, color: INK_SOFT }}>
                    None of the {report.permissions?.length ?? 0} permissions requested
                    are ones this model weights.
                  </Typography>
                )}
              </Panel>

              <Panel
                title="Code observations"
                subtitle="References found in the DEX. Those the manifest does not corroborate are shown but do not score."
              >
                {report.dex_findings?.map((d) => (
                  <Box key={d.indicator} sx={{
                    display: 'flex', gap: 1.5, py: 0.6, borderBottom: `1px solid ${RULE}`,
                    opacity: d.corroborated ? 1 : 0.55,
                  }}>
                    <Typography sx={{
                      fontFamily: MONO, fontSize: 11.5, minWidth: 26, fontWeight: 700,
                      color: d.corroborated ? (d.weight >= 7 ? CRITICAL : HIGH) : GREY_MUTED,
                    }}>
                      {d.corroborated ? `+${d.weight}` : '—'}
                    </Typography>
                    <Box>
                      <Typography sx={{ fontFamily: MONO, fontSize: 11.5, color: INK }}>
                        {d.indicator}
                      </Typography>
                      <Typography sx={{ fontSize: 11.5, color: INK_SOFT }}>{d.why}</Typography>
                      {d.note && (
                        <Typography sx={{ fontSize: 11, color: GREY_MUTED, fontStyle: 'italic' }}>
                          {d.note}
                        </Typography>
                      )}
                    </Box>
                  </Box>
                ))}
                {report.other_findings?.map((o) => (
                  <Box key={o.title} sx={{
                    display: 'flex', gap: 1.5, py: 0.6, borderBottom: `1px solid ${RULE}`,
                  }}>
                    <Typography sx={{
                      fontFamily: MONO, fontSize: 11.5, minWidth: 26, color: HIGH, fontWeight: 700,
                    }}>
                      +{o.weight}
                    </Typography>
                    <Box>
                      <Typography sx={{ fontSize: 12, color: INK, fontWeight: 600 }}>
                        {o.title}
                      </Typography>
                      <Typography sx={{ fontSize: 11.5, color: INK_SOFT }}>{o.why}</Typography>
                    </Box>
                  </Box>
                ))}
              </Panel>

              {(report.domains?.length > 0 || report.ips?.length > 0) && (
                <Panel
                  title="Network endpoints embedded in the package"
                  subtitle="Extracted from DEX strings. Toolchain and library hosts are filtered out."
                >
                  {report.domains?.map((d) => <Chip key={d} tone={CYAN}>{d}</Chip>)}
                  {report.ips?.map((i) => <Chip key={i} tone={HIGH}>{i}</Chip>)}
                </Panel>
              )}
            </>
          )}
        </Box>
      </Box>
    </Box>
  );
}
