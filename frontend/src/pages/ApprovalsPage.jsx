import { useEffect, useState } from 'react';
import {
  Box, Typography, Button, Chip, CircularProgress, Alert,
} from '@mui/material';
import Sidebar from '../components/layout/Sidebar';
import TopBar from '../components/layout/TopBar';
import { listPendingAccounts, decideAccount } from '../services/forensics';
import { describeError } from '../services/api';
import { useCurrentUser } from '../services/session';

/**
 * The approval queue.
 *
 * Every other consequential act in this system is recorded, attributed and
 * visible in the application. Approving an officer — the act that decides who
 * may touch evidence at all — was the exception: it required the Django admin.
 *
 * The audit entry is written by a signal on the User model, so a decision made
 * here and a decision made in the admin are recorded identically. This page
 * adds a place to make the decision, not a second version of the truth.
 */
function ApprovalsPage() {
  const user = useCurrentUser();
  const isAdmin = user?.is_superuser || user?.role === 'admin';

  const [queue, setQueue] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');

  const load = () =>
    listPendingAccounts()
      .then((data) => { setQueue(data); setError(''); })
      .catch((err) => {
        setQueue({ pending: [], approved_count: null });
        setError(describeError(err, 'Could not load the approval queue.'));
      });

  useEffect(() => { if (isAdmin) load(); }, [isAdmin]);

  const decide = async (username, decision) => {
    setBusy(username);
    try {
      await decideAccount(username, decision);
      await load();
    } catch (err) {
      setError(describeError(err, `Could not ${decision} ${username}.`));
    } finally {
      setBusy('');
    }
  };

  return (
    <Box sx={{ display: 'flex', backgroundColor: '#080B14', minHeight: '100vh' }}>
      <Sidebar />
      <Box sx={{ flexGrow: 1, minWidth: 0 }}>
        <TopBar />
        <Box sx={{ p: 2.5 }}>
          <Typography sx={{ fontSize: 20, fontWeight: 700, color: '#E5E7EB' }}>
            Account approvals
          </Typography>
          <Typography sx={{ fontSize: 12.5, color: 'rgba(229,231,235,0.55)', mb: 2.5 }}>
            An account holds no access until it is approved here. Every decision is
            attributed to the officer who made it and written to the audit log.
          </Typography>

          {!isAdmin ? (
            <Alert severity="info">
              Approving accounts requires Administrator clearance.
              {user ? ` Your account holds ${user.role}.` : ''}
            </Alert>
          ) : (
            <>
              {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

              {queue === null ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
                  <CircularProgress sx={{ color: '#00D4FF' }} />
                </Box>
              ) : queue.pending.length === 0 ? (
                <Alert severity="success">
                  No applications waiting.
                  {queue.approved_count != null
                    && ` ${queue.approved_count} account(s) currently approved.`}
                </Alert>
              ) : (
                queue.pending.map((account) => (
                  <Box key={account.username} sx={{
                    mb: 1.5, p: 2, borderRadius: 2,
                    border: '1px solid rgba(255,255,255,0.07)',
                    backgroundColor: 'rgba(255,255,255,0.02)',
                    display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap',
                  }}>
                    <Box sx={{ minWidth: 0 }}>
                      <Typography sx={{ fontSize: 14, color: '#E5E7EB' }}>
                        {account.username}
                      </Typography>
                      <Typography sx={{ fontSize: 12, color: 'rgba(229,231,235,0.55)' }}>
                        {account.department || '—'} · badge {account.badge_id || '—'}
                      </Typography>
                    </Box>
                    <Chip label={`requested: ${account.role}`} size="small" sx={{
                      backgroundColor: 'rgba(0,212,255,0.14)', color: '#00D4FF', fontSize: 11,
                    }} />
                    <Box sx={{ flexGrow: 1 }} />
                    <Button
                      size="small" variant="outlined" disabled={busy === account.username}
                      onClick={() => decide(account.username, 'approve')}
                      sx={{ fontSize: 11.5, borderColor: 'rgba(0,230,138,0.5)', color: '#00E68A' }}
                    >
                      Approve
                    </Button>
                    <Button
                      size="small" variant="outlined" disabled={busy === account.username}
                      onClick={() => decide(account.username, 'reject')}
                      sx={{ fontSize: 11.5, borderColor: 'rgba(255,59,92,0.5)', color: '#FF3B5C' }}
                    >
                      Reject
                    </Button>
                  </Box>
                ))
              )}
            </>
          )}
        </Box>
      </Box>
    </Box>
  );
}

export default ApprovalsPage;
