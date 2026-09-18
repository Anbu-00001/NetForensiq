import { useRef, useState } from 'react';
import {
  Box, Typography, Button, TextField, Alert, LinearProgress, MenuItem, Link,
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
  CYAN, CRITICAL, HIGH, MEDIUM, INTACT, MONO,
} from '../theme/tokens';

/**
 * Examining a submitted Android package.
 *
 * Why there is no score on this screen
 * ------------------------------------
 * There used to be: a number out of 100, added up from permissions and strings.
 * It called a Flipkart build pulled off a phone a 100/100 remote access trojan,
 * because the app checks whether the handset is rooted — which is an anti-fraud
 * control — and because Google Play lets UPI apps hold SMS permissions. A
 * number like that cannot be defended in a courtroom, and it was not true.
 *
 * What replaced it is a tier: the strongest kind of evidence the engine
 * actually has. Tier 3 and 4 name what was found and show the call path that
 * found it. Tier 1 says only that nothing was established — never that the app
 * is safe. Tier 0 says the examination did not finish, which is a different
 * thing from finding nothing, and is never dressed up as a clean result.
 *
 * Every finding carries the measurement behind it: how many apps in the
 * legitimate reference corpus it fired on, and how high its false-positive rate
 * could still plausibly be. Findings that fire on legitimate apps are shown
 * greyed under "not established" and cannot move the tier.
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
    tone: GREY,
  },
];

const TIER_TONE = { 4: CRITICAL, 3: CRITICAL, 2: MEDIUM, 1: GREY, 0: GREY };

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

/** How often this signal fired on apps known to be legitimate. */
function Baseline({ baseline }) {
  if (!baseline) return null;
  const { status, benign_fired: fired, benign_n: total, upper_bound_95: bound } = baseline;
  if (status === 'unmeasured') {
    return (
      <Typography sx={{ fontSize: 11, color: GREY_MUTED, mt: 0.3 }}>
        Not yet measured against a legitimate corpus, so it cannot affect the assessment.
      </Typography>
    );
  }
  return (
    <Typography sx={{ fontSize: 11, color: GREY_MUTED, mt: 0.3 }}>
      Fired on {fired} of {total} legitimate apps
      {baseline.measured_at ? ` measured ${baseline.measured_at.slice(0, 10)}` : ''}
      {bound != null ? ` · false-positive rate could still be up to ${(bound * 100).toFixed(1)}%` : ''}
      {status === 'experimental' && baseline.benign_examples?.length
        ? ` · e.g. ${baseline.benign_examples.slice(0, 3).join(', ')}`
        : ''}
    </Typography>
  );
}

function Sources({ sources }) {
  if (!sources?.length) return null;
  return (
    <Box sx={{ mt: 0.6 }}>
      <Label>Why this is a known technique</Label>
      {sources.map((s) => (
        <Typography key={s.url} sx={{ fontSize: 11.5, color: INK_SOFT }}>
          <Link href={s.url} target="_blank" rel="noreferrer" sx={{ color: CYAN }}>
            {s.title}
          </Link>
          {' — '}{s.publisher}, {s.date}
          {!s.verified && (
            <span title="Only a secondary account of this report was read.">
              {' '}(secondary source)
            </span>
          )}
        </Typography>
      ))}
    </Box>
  );
}

function Evidence({ items }) {
  if (!items?.length) return null;
  return (
    <Box sx={{ mt: 0.6 }}>
      {items.map((item, index) => (
        <Box key={index} sx={{ borderLeft: `2px solid ${RULE_STRONG}`, pl: 1.2, py: 0.4, mb: 0.5 }}>
          {item.caller ? (
            <>
              <Typography sx={{ fontFamily: MONO, fontSize: 11.5, color: INK }}>
                {item.caller}
                {item.calls ? ` → ${item.calls}` : ''}
              </Typography>
              <Typography sx={{ fontSize: 11, color: GREY_MUTED }}>
                {item.attribution?.kind === 'app' && 'in the package\'s own code'}
                {item.attribution?.kind === 'unattributed' && 'in obfuscated code (cannot be attributed to a library)'}
                {item.attribution?.kind === 'library' && `in ${item.attribution.name}`}
                {item.routes?.length ? ` · routes ${item.routes.join(', ')}` : ''}
              </Typography>
              {item.path_from_component?.length > 1 && (
                <Typography sx={{ fontFamily: MONO, fontSize: 10.5, color: GREY_MUTED }}>
                  reached from {item.path_from_component[0]}
                </Typography>
              )}
            </>
          ) : item.manifest ? (
            <Typography sx={{ fontSize: 11.5, color: INK }}>
              <span style={{ fontFamily: MONO }}>{item.component}</span> — {item.manifest}
            </Typography>
          ) : item.value ? (
            <Typography sx={{ fontFamily: MONO, fontSize: 11.5, color: INK, wordBreak: 'break-all' }}>
              {item.value}
            </Typography>
          ) : (
            <Typography sx={{ fontFamily: MONO, fontSize: 11, color: INK_SOFT }}>
              {JSON.stringify(item)}
            </Typography>
          )}
        </Box>
      ))}
    </Box>
  );
}

function Assessment({ report }) {
  const a = report.assessment;
  const tone = TIER_TONE[a.tier] ?? GREY;
  return (
    <Panel
      title="Assessment"
      subtitle={`Exhibit ${report.exhibit_number} — ${report.provenance_label}`}
    >
      <Box sx={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'flex-start' }}>
        <Box sx={{ minWidth: 300, flex: 1 }}>
          <Typography sx={{
            fontSize: 17, fontWeight: 700, color: tone, textTransform: 'uppercase',
            letterSpacing: 0.4,
          }}>
            {a.label}
          </Typography>
          <Typography sx={{ fontSize: 11, color: GREY_MUTED, fontFamily: MONO }}>
            evidence tier {a.tier} of 4
          </Typography>
          <Typography sx={{ fontSize: 12.5, color: INK_SOFT, mt: 0.8 }}>{a.meaning}</Typography>
          {a.summary && a.summary !== a.meaning && (
            <Typography sx={{ fontSize: 12.5, color: INK, mt: 0.6 }}>{a.summary}</Typography>
          )}
        </Box>
        <Box sx={{ minWidth: 280, flex: 1 }}>
          <Label>Package</Label>
          <Typography sx={{ fontFamily: MONO, fontSize: 12.5, color: INK, mb: 0.8 }}>
            {report.identity?.package || '— not parsed —'}
            {report.identity?.version_name ? `  v${report.identity.version_name}` : ''}
          </Typography>
          <Label>SHA-256 of the sealed exhibit</Label>
          <Typography sx={{
            fontFamily: MONO, fontSize: 10.5, color: INK, wordBreak: 'break-all', mb: 0.8,
          }}>
            {report.sealed_sha256}
          </Typography>
          <Typography sx={{ fontSize: 11, color: GREY_MUTED }}>
            {report.identity?.label ? `“${report.identity.label}” · ` : ''}
            minSdk {report.identity?.min_sdk ?? '?'} · targetSdk {report.identity?.target_sdk ?? '?'}
            {report.code ? ` · ${report.code.dex_files} dex` : ''}
            {report.unwrapped_from ? ` · unwrapped from ${report.unwrapped_from}` : ''}
          </Typography>
        </Box>
      </Box>

      {a.families?.length > 0 && (
        <Box sx={{ mt: 1.6, borderTop: `1px solid ${RULE}`, pt: 1.2 }}>
          <Label>Category</Label>
          {a.families.map((f) => (
            <Box key={f.category} sx={{ mb: 0.8 }}>
              <Typography sx={{ fontSize: 13.5, fontWeight: 700, color: CRITICAL }}>
                {f.category}{f.product ? ` — ${f.product}` : ''}
              </Typography>
              <Typography sx={{ fontSize: 12, color: INK_SOFT }}>{f.definition}</Typography>
              <Typography sx={{ fontSize: 11, color: GREY_MUTED }}>
                Category defined by{' '}
                <Link href={f.definition_source} target="_blank" rel="noreferrer" sx={{ color: CYAN }}>
                  Google Play Protect
                </Link>
                {' · established by '}{f.established_by.join(', ')}
              </Typography>
            </Box>
          ))}
        </Box>
      )}

      {a.attack?.length > 0 && (
        <Box sx={{ mt: 1.2 }}>
          <Label>MITRE ATT&CK for Mobile</Label>
          {a.attack.map((t) => (
            <Chip key={t.id} tone={CRITICAL} title={t.name}>{t.id} {t.name}</Chip>
          ))}
        </Box>
      )}

      {a.basis?.length > 0 && (
        <Box sx={{ mt: 1.2 }}>
          <Label>What the tier rests on</Label>
          {a.basis.map((b) => (
            <Typography key={b.id} sx={{ fontSize: 12, color: INK }}>
              • {b.title}
              <span style={{ color: GREY_MUTED, fontFamily: MONO, fontSize: 11 }}>
                {' '}({b.id}{b.benign_n ? `, 0 of ${b.benign_n} legitimate apps` : ''})
              </span>
            </Typography>
          ))}
        </Box>
      )}

      {a.not_established?.length > 0 && (
        <Box sx={{ mt: 1.2, bgcolor: PANEL_ALT, p: 1.2 }}>
          <Label>Observed, but not treated as evidence</Label>
          {a.not_established.map((n) => (
            <Typography key={n.id} sx={{ fontSize: 12, color: GREY }}>
              • {n.title}
              <span style={{ fontFamily: MONO, fontSize: 11 }}>
                {' '}({n.status === 'unmeasured'
                  ? 'not measured against legitimate apps'
                  : `also fires on ${n.benign_fired} of ${n.benign_n} legitimate apps`})
              </span>
            </Typography>
          ))}
        </Box>
      )}

      {report.errors?.length > 0 && (
        <Alert severity="info" sx={{ mt: 1.5, fontSize: 12 }}>
          {report.errors.slice(0, 6).join(' · ')}
        </Alert>
      )}
    </Panel>
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

  const behaviours = report?.behaviours ?? [];
  const capabilities = (report?.capabilities ?? []).filter((c) => c.present);
  const endpoints = report?.endpoints;
  const intel = report?.intel;

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
          <Typography sx={{ fontSize: 12.5, color: INK_SOFT, mt: 0.6, mb: 2.4, maxWidth: 820 }}>
            The package is sealed and hashed before anything opens it, and the examination runs
            against the sealed copy in a separate, memory-limited process. Analysis is entirely
            static — the sample is never executed — and every conclusion is shown with the code
            that produced it and with how often that signal fires on legitimate apps.
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
              <Assessment report={report} />

              {intel?.matches?.length > 0 && (
                <Panel
                  title="Listed in published indicators"
                  subtitle={`Checked against ${intel.checked_against?.source} · ${intel.checked_against?.licence}`}
                >
                  {intel.matches.map((m, i) => (
                    <Box key={i} sx={{
                      borderLeft: `3px solid ${m.strength === 'identity' ? CRITICAL : MEDIUM}`,
                      pl: 1.2, py: 0.6, mb: 0.8,
                    }}>
                      <Typography sx={{ fontSize: 12.5, color: INK, fontWeight: 600 }}>
                        {m.product} — {m.kind.replace(/_/g, ' ')}
                      </Typography>
                      <Typography sx={{ fontFamily: MONO, fontSize: 11, color: INK_SOFT, wordBreak: 'break-all' }}>
                        {m.value}
                      </Typography>
                      <Typography sx={{ fontSize: 11, color: GREY_MUTED }}>
                        {m.strength === 'identity'
                          ? 'Identity match — the file or its signing key is the listed one.'
                          : 'Supporting only: package names and domains can be reused, so this does not decide the tier.'}
                        {m.snapshot ? ` · snapshot ${m.snapshot}` : ''}
                      </Typography>
                    </Box>
                  ))}
                </Panel>
              )}

              {behaviours.length > 0 && (
                <Panel
                  title="Behaviours found in the code"
                  subtitle="Combinations that published threat research documents in malware. Each shows the calls that establish it."
                >
                  {behaviours.map((b) => {
                    const validated = b.baseline?.status === 'validated';
                    return (
                      <Box key={b.id} sx={{
                        border: `1px solid ${validated ? RULE_STRONG : RULE}`,
                        borderLeft: `3px solid ${validated ? CRITICAL : GREY_MUTED}`,
                        p: 1.4, mb: 1.2, bgcolor: validated ? PAPER : PANEL_ALT,
                      }}>
                        <Typography sx={{
                          fontSize: 13.5, fontWeight: 700, color: validated ? CRITICAL : GREY,
                        }}>
                          {b.title}
                        </Typography>
                        <Typography sx={{ fontSize: 12, color: INK_SOFT, mt: 0.4 }}>
                          {b.description}
                        </Typography>
                        {!validated && (
                          <Typography sx={{ fontSize: 11.5, color: GREY, mt: 0.5, fontStyle: 'italic' }}>
                            Reported but not used in the assessment — see the measurement below.
                          </Typography>
                        )}
                        <Baseline baseline={b.baseline} />
                        {Object.entries(b.evidence || {}).map(([capability, items]) => (
                          <Box key={capability} sx={{ mt: 0.8 }}>
                            <Label>{capability}</Label>
                            <Evidence items={items} />
                          </Box>
                        ))}
                        <Typography sx={{ fontSize: 11.5, color: GREY_MUTED, mt: 0.8 }}>
                          <strong>Legitimate apps that look similar:</strong> {b.legitimate_lookalikes}
                        </Typography>
                        <Box sx={{ mt: 0.6 }}>
                          {b.attack?.map((t) => <Chip key={t.id} tone={GREY}>{t.id} {t.name}</Chip>)}
                        </Box>
                        <Sources sources={b.sources} />
                      </Box>
                    );
                  })}
                </Panel>
              )}

              {report.integrity?.findings?.length > 0 && (
                <Panel
                  title="How the package is built"
                  subtitle="Structural facts about the file itself — forged headers are how a package hides from analysis tools while still installing."
                >
                  {report.integrity.findings.map((f) => (
                    <Box key={f.id} sx={{ borderBottom: `1px solid ${RULE}`, py: 0.9 }}>
                      <Typography sx={{ fontSize: 12.5, fontWeight: 600, color: INK }}>
                        {f.title}
                      </Typography>
                      <Typography sx={{ fontSize: 11.5, color: INK_SOFT }}>{f.meaning}</Typography>
                      <Typography sx={{ fontFamily: MONO, fontSize: 11, color: GREY, mt: 0.3 }}>
                        {JSON.stringify(f.evidence?.examples?.[0] ?? {})}
                      </Typography>
                      <Baseline baseline={f.baseline} />
                      <Sources sources={f.sources} />
                    </Box>
                  ))}
                </Panel>
              )}

              <Panel
                title="What the code can do"
                subtitle="An inventory, not a verdict: legitimate apps hold these capabilities too, and the counts say how often."
              >
                {capabilities.length === 0 ? (
                  <Typography sx={{ fontSize: 12.5, color: INK_SOFT }}>
                    None of the capabilities this engine looks for were found in the
                    package&apos;s own code.
                  </Typography>
                ) : capabilities.map((c) => (
                  <Box key={c.id} sx={{ borderBottom: `1px solid ${RULE}`, py: 0.8 }}>
                    <Typography sx={{ fontSize: 12.5, color: INK, fontWeight: 600 }}>
                      {c.title}
                      {c.evidence_total > 1 && (
                        <span style={{ color: GREY_MUTED, fontFamily: MONO, fontSize: 11 }}>
                          {' '}({c.evidence_total} places)
                        </span>
                      )}
                    </Typography>
                    <Evidence items={c.evidence?.slice(0, 3)} />
                    {c.library_only_occurrences > 0 && (
                      <Typography sx={{ fontSize: 11, color: GREY_MUTED }}>
                        {c.library_only_occurrences} further occurrence(s) inside bundled
                        libraries, which are not counted as this app&apos;s behaviour.
                      </Typography>
                    )}
                    <Baseline baseline={c.baseline} />
                  </Box>
                ))}
              </Panel>

              {report.identity && (
                <Panel
                  title="Identity and signing"
                  subtitle="Who the package says it is, and which key signed it."
                >
                  <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                    <Box sx={{ minWidth: 260, flex: 1 }}>
                      <Label>Signing schemes</Label>
                      <Box sx={{ mb: 1 }}>
                        {Object.entries(report.identity.signing?.schemes ?? {}).map(([k, v]) => (
                          <Chip key={k} tone={v ? INTACT : GREY_MUTED}>{k}{v ? ' ✓' : ' ✗'}</Chip>
                        ))}
                      </Box>
                      {report.identity.signing?.certificates?.map((c) => (
                        <Box key={c.sha256} sx={{ mb: 1 }}>
                          <Typography sx={{ fontSize: 11.5, color: INK }}>{c.subject}</Typography>
                          <Typography sx={{ fontFamily: MONO, fontSize: 10.5, color: GREY, wordBreak: 'break-all' }}>
                            SHA-256 {c.sha256}
                          </Typography>
                          <Typography sx={{ fontSize: 11, color: GREY_MUTED }}>
                            {c.self_signed ? 'self-signed' : 'issued by a CA'}
                            {c.debug_certificate ? ' · Android debug certificate (Play does not accept these)' : ''}
                            {' · valid '}{c.not_before?.slice(0, 10)} to {c.not_after?.slice(0, 10)}
                          </Typography>
                          {c.subject_anomalies?.map((anomaly) => (
                            <Typography key={anomaly.id} sx={{ fontSize: 11, color: MEDIUM }}>
                              {anomaly.detail}
                            </Typography>
                          ))}
                        </Box>
                      ))}
                    </Box>
                    <Box sx={{ minWidth: 260, flex: 1 }}>
                      <Label>Permissions requested ({report.identity.permissions?.length ?? 0})</Label>
                      {(report.identity.permissions ?? []).map((p) => (
                        <Typography key={p.name} sx={{ fontSize: 11.5, color: INK_SOFT }}>
                          <span style={{ fontFamily: MONO }}>
                            {p.name.replace('android.permission.', '')}
                          </span>
                          <span style={{ color: GREY_MUTED }}>
                            {' '}{p.protection_level || (p.defined_by_aosp ? '' : 'not an AOSP permission')}
                          </span>
                        </Typography>
                      ))}
                      <Typography sx={{ fontSize: 11, color: GREY_MUTED, mt: 0.6 }}>
                        Protection levels are Android&apos;s own. A permission is a capability the
                        user or platform grants, not evidence of intent.
                      </Typography>
                    </Box>
                  </Box>
                </Panel>
              )}

              {endpoints && (endpoints.app_total > 0 || endpoints.sdk_total > 0) && (
                <Panel
                  title="Network endpoints written into the code"
                  subtitle={`${endpoints.app_total} the package's own code names · ${endpoints.sdk_total} belonging to bundled SDKs · ${endpoints.templates_suppressed} URL templates ignored`}
                >
                  <Label>Named by this package</Label>
                  <Box sx={{ mb: 1 }}>
                    {endpoints.app.length === 0
                      ? <Typography sx={{ fontSize: 12, color: INK_SOFT }}>None.</Typography>
                      : endpoints.app.map((e) => (
                        <Chip key={e.host} tone={CYAN} title={e.examples?.join('\n')}>{e.host}</Chip>
                      ))}
                  </Box>
                  {endpoints.sdk.length > 0 && (
                    <>
                      <Label>Belonging to bundled SDKs — not this app&apos;s traffic</Label>
                      <Box>
                        {endpoints.sdk.slice(0, 60).map((e) => (
                          <Chip key={e.host} tone={GREY_MUTED} title={e.sdk}>{e.host}</Chip>
                        ))}
                      </Box>
                    </>
                  )}
                </Panel>
              )}

              {report.correlation && (
                <Panel
                  title="Seen on the network"
                  subtitle={`${report.correlation.checked_hosts} names and ${report.correlation.checked_ips} addresses from this package, checked against captures already in evidence. Corroboration only — it does not change the tier.`}
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
                        <Box key={`f${i}`} sx={{ borderLeft: `3px solid ${HIGH}`, pl: 1.2, py: 0.7, mb: 0.8 }}>
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
                title="How this examination was made"
                subtitle="So the result can be repeated, and its limits read alongside it."
              >
                <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap', mb: 1 }}>
                  <Box sx={{ minWidth: 240 }}>
                    <Label>Engine</Label>
                    <Typography sx={{ fontFamily: MONO, fontSize: 11, color: INK_SOFT }}>
                      apk_engine {report.engine?.engine} · androguard {report.engine?.androguard} ·
                      apkInspector {report.engine?.apkInspector}
                      {report.engine?.seconds ? ` · ${report.engine.seconds}s` : ''}
                    </Typography>
                  </Box>
                  <Box sx={{ minWidth: 240 }}>
                    <Label>Reference measurement</Label>
                    <Typography sx={{ fontSize: 11, color: INK_SOFT }}>
                      {report.engine?.baselines?.corpus?.benign
                        ? `${report.engine.baselines.corpus.benign} legitimate and ${report.engine.baselines.corpus.malicious} malicious apps, measured ${report.engine.baselines.measured_at?.slice(0, 10)}`
                        : 'No baseline measurement is loaded, so no signal can raise the tier.'}
                    </Typography>
                  </Box>
                </Box>
                {report.container && (
                  <Box sx={{ mb: 1 }}>
                    <Label>The archive as received</Label>
                    <Typography sx={{ fontSize: 11.5, color: INK_SOFT }}>
                      {report.container.entries} entries ·{' '}
                      {report.container.encryption?.length
                        ? `encrypted (${report.container.encryption.join(', ')}) — a sample-sharing convention, recorded but not scored`
                        : 'not encrypted'}
                      {report.container.safety?.length
                        ? ` · ${report.container.safety.map((s) => s.title).join('; ')}`
                        : ''}
                    </Typography>
                  </Box>
                )}
                <Label>Limits of this examination</Label>
                {(report.limits ?? []).map((limit) => (
                  <Typography key={limit} sx={{ fontSize: 11.5, color: GREY, mb: 0.3 }}>
                    • {limit}
                  </Typography>
                ))}
              </Panel>
            </>
          )}
        </Box>
      </Box>
    </Box>
  );
}
