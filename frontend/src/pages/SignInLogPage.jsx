import { useEffect, useState } from 'react';
import {
  Box, Typography, Alert, TextField, ToggleButton, ToggleButtonGroup,
} from '@mui/material';
import Sidebar from '../components/layout/Sidebar';
import TopBar from '../components/layout/TopBar';
import ClassificationBanner from '../components/layout/ClassificationBanner';
import { listSignInAttempts } from '../services/forensics';
import { useCurrentUser } from '../services/session';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, RULE, PANEL, PANEL_ALT, PAPER,
  CRITICAL, MEDIUM, INTACT, CYAN, MONO,
} from '../theme/tokens';

/**
 * Who tried to sign in, when, from where, and whether it worked.
 *
 * Why this page exists
 * --------------------
 * The sign-in screen tells every officer that attempts are recorded with a
 * timestamp, a username and a source address. That was true and unreadable:
 * the rows were written faithfully and the only way to see one was a Django
 * shell. A promise nobody can check is a promise on a poster, and "secure
 * storage and **access logs**" is a stated requirement rather than a nicety.
 *
 * The column that matters
 * -----------------------
 * `outcome` distinguishes **refused** from **server fault**, and that
 * distinction was a defect before it was a feature. The sign-in view caught
 * every exception as a bad password, so a locked database wrote "credentials
 * rejected" against a named officer and counted it toward locking their
 * account out. The screen in front of them said the fault was the server's
 * while the permanent record said the fault was theirs — and the permanent
 * record is the artefact that goes to a court.
 *
 * Failed usernames are shown as typed, never masked. A run of attempts against
 * a username that does not exist is what credential stuffing looks like, and
 * hiding the string would hide the attack.
 */

const OUTCOME_INK = {
  success: INTACT,
  refused: CRITICAL,
  'server fault': MEDIUM,
  'signed out': GREY_MUTED,
};

function Stat({ label, value, tone }) {
  return (
    <Box sx={{
      px: 1.6, py: 1.1, borderRadius: 1, minWidth: 118,
      border: `1px solid ${RULE}`, backgroundColor: PAPER,
      borderTop: `3px solid ${tone}`,
    }}>
      <Typography sx={{ fontSize: 20, fontWeight: 700, fontFamily: MONO, color: INK, lineHeight: 1.1 }}>
        {value}
      </Typography>
      <Typography sx={{ fontSize: 10.5, color: GREY, lineHeight: 1.35 }}>
        {label}
      </Typography>
    </Box>
  );
}

function stamp(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} `
       + `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function SignInLogPage() {
  const user = useCurrentUser();
  const isAdmin = user?.is_superuser || user?.role === 'admin';

  const [data, setData] = useState(null);
  const [outcome, setOutcome] = useState('all');
  const [username, setUsername] = useState('');
  const [error, setError] = useState('');
  // Seeded from the clearance rather than set inside the effect: a viewer
  // never issues a request, so there is nothing for them to be waiting on and
  // an effect that immediately clears the flag is a wasted render pass.
  const [loading, setLoading] = useState(isAdmin);

  useEffect(() => {
    if (!isAdmin) return undefined;
    let live = true;
    // Debounced, so typing a username does not fire a request per keystroke
    // against a table that grows without bound.
    const timer = setTimeout(() => {
      setLoading(true);
      listSignInAttempts({
        outcome: outcome === 'all' ? undefined : outcome,
        username: username.trim() || undefined,
      })
        .then((rows) => { if (live) { setData(rows); setError(''); } })
        .catch(() => { if (live) setError('The sign-in log could not be read.'); })
        .finally(() => { if (live) setLoading(false); });
    }, 250);
    return () => { live = false; clearTimeout(timer); };
  }, [isAdmin, outcome, username]);

  const rows = data?.attempts ?? [];
  const recent = data?.last_24h;

  return (
    <Box sx={{ minHeight: '100vh', backgroundColor: PAPER }}>
      <ClassificationBanner fixed />
      <Box sx={{ display: 'flex' }}>
        <Sidebar />
        <Box sx={{ flexGrow: 1, minWidth: 0 }}>
          <TopBar />
          <Box sx={{ p: 2.5 }}>
            <Typography sx={{ fontSize: 19, fontWeight: 700, color: INK, mb: 0.3 }}>
              Sign-in log
            </Typography>
            <Typography sx={{ fontSize: 12.5, color: GREY, mb: 2, lineHeight: 1.6 }}>
              Every attempt this installation has recorded, successful or not,
              with the username as it was typed and the address it came from.
              Attempts refused by the rate limiter are here too — the point at
              which traffic becomes worth looking at is the point a log must not
              go quiet.
            </Typography>

            {!isAdmin ? (
              <Alert severity="warning" sx={{ fontSize: 12.5 }}>
                The sign-in log names officers and source addresses, so it
                requires Administrator clearance. Your clearance is{' '}
                {user?.role ?? 'unknown'}.
              </Alert>
            ) : (
              <>
                {recent && (
                  <Box sx={{ display: 'flex', gap: 1.2, flexWrap: 'wrap', mb: 2 }}>
                    <Stat label="signed in, last 24h" value={recent.success} tone={INTACT} />
                    <Stat label="refused, last 24h" value={recent.refused} tone={CRITICAL} />
                    <Stat label="server faults, last 24h" value={recent.server_fault} tone={MEDIUM} />
                    <Stat label="attempts on record" value={data.total_matching} tone={GREY_MUTED} />
                  </Box>
                )}

                <Box sx={{ display: 'flex', gap: 1.5, mb: 1.5, flexWrap: 'wrap', alignItems: 'center' }}>
                  <ToggleButtonGroup
                    size="small" exclusive value={outcome}
                    onChange={(_e, next) => next && setOutcome(next)}
                    sx={{
                      '& .MuiToggleButton-root': {
                        fontSize: 11.5, py: 0.4, px: 1.4, textTransform: 'none',
                        color: GREY, borderColor: RULE,
                        '&.Mui-selected': {
                          color: PAPER, backgroundColor: INK,
                          '&:hover': { backgroundColor: INK_SOFT },
                        },
                      },
                    }}
                  >
                    <ToggleButton value="all">Everything</ToggleButton>
                    <ToggleButton value="failed">Failed only</ToggleButton>
                    <ToggleButton value="login_success">Successful</ToggleButton>
                  </ToggleButtonGroup>

                  <TextField
                    size="small" placeholder="Filter by username"
                    value={username} onChange={(e) => setUsername(e.target.value)}
                    sx={{
                      minWidth: 200,
                      '& .MuiOutlinedInput-root': {
                        fontSize: 12.5, backgroundColor: PAPER,
                        '& fieldset': { borderColor: RULE },
                        '&.Mui-focused fieldset': { borderColor: CYAN },
                      },
                    }}
                  />
                </Box>

                {error && <Alert severity="error" sx={{ mb: 2, fontSize: 12.5 }}>{error}</Alert>}

                <Box sx={{ border: `1px solid ${RULE}`, borderRadius: 1, overflowX: 'auto' }}>
                  <Box component="table" sx={{
                    width: '100%', borderCollapse: 'collapse', minWidth: 860,
                  }}>
                    <Box component="thead">
                      <Box component="tr" sx={{ backgroundColor: PANEL }}>
                        {['When', 'Outcome', 'Username as typed', 'From', 'What was recorded'].map((h) => (
                          <Box
                            component="th" key={h}
                            sx={{
                              textAlign: 'left', px: 1.4, py: 0.9, fontSize: 10.5,
                              letterSpacing: 0.7, color: INK_SOFT, fontWeight: 700,
                              borderBottom: `1px solid ${RULE}`, whiteSpace: 'nowrap',
                            }}
                          >
                            {h.toUpperCase()}
                          </Box>
                        ))}
                      </Box>
                    </Box>
                    <Box component="tbody">
                      {rows.map((row, i) => (
                        <Box
                          component="tr" key={row.id}
                          sx={{ backgroundColor: i % 2 ? PANEL_ALT : PAPER }}
                        >
                          <Box component="td" sx={{
                            px: 1.4, py: 0.75, fontSize: 11.5, fontFamily: MONO,
                            color: INK, whiteSpace: 'nowrap',
                          }}>
                            {stamp(row.timestamp)}
                          </Box>
                          <Box component="td" sx={{ px: 1.4, py: 0.75, whiteSpace: 'nowrap' }}>
                            <Box component="span" sx={{
                              fontSize: 10.5, fontWeight: 700, letterSpacing: 0.4,
                              color: OUTCOME_INK[row.outcome] ?? GREY,
                            }}>
                              {row.outcome.toUpperCase()}
                            </Box>
                          </Box>
                          <Box component="td" sx={{
                            px: 1.4, py: 0.75, fontSize: 11.5, fontFamily: MONO, color: INK,
                          }}>
                            {row.username_attempted || '—'}
                            {/* An attempt against a username that does not
                                exist is the signature of credential stuffing,
                                so it is called out rather than left to be
                                inferred from the absence of a link. */}
                            {!row.account_exists && row.username_attempted && (
                              <Box component="span" sx={{
                                fontFamily: 'inherit', fontSize: 9.5, color: MEDIUM,
                                ml: 0.8, fontWeight: 700,
                              }}>
                                NO SUCH ACCOUNT
                              </Box>
                            )}
                          </Box>
                          <Box component="td" sx={{
                            px: 1.4, py: 0.75, fontSize: 11.5, fontFamily: MONO,
                            color: INK_SOFT, whiteSpace: 'nowrap',
                          }}>
                            {row.ip_address || '—'}
                          </Box>
                          <Box component="td" sx={{
                            px: 1.4, py: 0.75, fontSize: 11.5, color: GREY, lineHeight: 1.45,
                          }}>
                            {row.detail || row.action_label}
                          </Box>
                        </Box>
                      ))}
                      {!rows.length && !loading && (
                        <Box component="tr">
                          <Box component="td" colSpan={5} sx={{
                            px: 1.4, py: 2, fontSize: 12.5, color: GREY,
                          }}>
                            No attempt matches that filter.
                          </Box>
                        </Box>
                      )}
                    </Box>
                  </Box>
                </Box>

                {data && (
                  <Typography sx={{ fontSize: 11, color: GREY_MUTED, mt: 1, lineHeight: 1.5 }}>
                    Showing {rows.length} of {data.total_matching} matching.{' '}
                    {data.retention_note}
                  </Typography>
                )}
              </>
            )}
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

export default SignInLogPage;
