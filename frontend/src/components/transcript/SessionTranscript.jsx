import { useState } from 'react';
import { Box, Typography, Button, Alert, Chip, CircularProgress } from '@mui/material';
import { getFlowTranscript } from '../../services/forensics';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, PANEL, PANEL_ALT, RULE,
  CYAN, CRITICAL, MEDIUM, LOW, MONO,
} from '../../theme/tokens';

/**
 * The conversation, read back from the sealed capture.
 *
 * What this shows before it shows anything else
 * ---------------------------------------------
 * The caveats. A transcript that was rebuilt across a gap, or from segments
 * that contradicted each other, looks exactly like one that was not — and an
 * officer who reads the content first has already formed a view by the time
 * they reach the small print. So the warnings are above the transcript, not
 * below it, and an ambiguous reconstruction is labelled in the same red the
 * system uses for a broken seal.
 *
 * Credentials
 * -----------
 * A cleartext password is evidence and is not thrown away. It is also not put
 * on screen by default, because this window gets projected in briefings and
 * photographed. It takes a deliberate click, which is the same standard the
 * rest of the product applies to irreversible acts.
 *
 * Nothing here is fetched until asked for. Reconstruction reads the whole
 * exhibit to find one conversation, and doing that for every finding on a page
 * of three hundred would be indefensible.
 */

function Caveats({ transcript }) {
  const caveats = transcript.caveats ?? [];
  if (!caveats.length && transcript.reconstruction_complete !== false) return null;

  const ambiguous = transcript.reconstruction_ambiguous;
  return (
    <Alert
      severity={ambiguous ? 'error' : 'warning'}
      icon={false}
      sx={{
        mb: 2, fontSize: 12.5, borderRadius: 1,
        border: `1px solid ${ambiguous ? CRITICAL : MEDIUM}55`,
        backgroundColor: ambiguous ? 'rgba(179,38,30,0.06)' : 'rgba(138,97,0,0.07)',
        color: INK_SOFT,
      }}
    >
      <Typography sx={{
        fontSize: 11, fontWeight: 700, letterSpacing: 1, mb: 0.8,
        color: ambiguous ? CRITICAL : MEDIUM, fontFamily: MONO,
      }}>
        {ambiguous
          ? 'THIS RECONSTRUCTION IS NOT THE ONLY POSSIBLE ONE'
          : 'THIS RECONSTRUCTION IS INCOMPLETE'}
      </Typography>
      <Box component="ul" sx={{ m: 0, pl: 2.2 }}>
        {caveats.map((line) => (
          <Typography key={line} component="li" sx={{ fontSize: 12.5, mb: 0.4 }}>
            {line}
          </Typography>
        ))}
      </Box>
    </Alert>
  );
}

function Line({ direction, children }) {
  const fromClient = direction === 'client';
  return (
    <Box sx={{
      display: 'flex', gap: 1.5, py: 0.5, px: 1,
      borderLeft: `2px solid ${fromClient ? LOW : GREY_MUTED}`,
      backgroundColor: fromClient ? 'transparent' : PANEL_ALT,
    }}>
      <Typography sx={{
        fontFamily: MONO, fontSize: 10.5, color: GREY, width: 52, flexShrink: 0,
        pt: '2px',
      }}>
        {fromClient ? 'CLIENT' : 'SERVER'}
      </Typography>
      <Box sx={{ minWidth: 0, flexGrow: 1 }}>{children}</Box>
    </Box>
  );
}

function Sensitive({ value }) {
  const [shown, setShown] = useState(false);
  if (shown) {
    return (
      <Box component="span" sx={{
        fontFamily: MONO, fontSize: 12.5, color: CRITICAL, fontWeight: 600,
      }}>
        {value}
      </Box>
    );
  }
  return (
    <Button
      size="small" onClick={() => setShown(true)}
      sx={{
        fontSize: 11, py: 0, px: 0.8, minWidth: 0, textTransform: 'none',
        color: CRITICAL, border: `1px dashed ${CRITICAL}66`,
      }}
    >
      {value.length} character(s) withheld — click to reveal
    </Button>
  );
}

function Exchange({ transcript }) {
  const events = transcript.events ?? [];
  if (!events.length) return null;

  return (
    <Box sx={{
      border: `1px solid ${RULE}`, borderRadius: 1, overflow: 'hidden',
      backgroundColor: '#FFFFFF',
    }}>
      {events.map((event, index) => (
        <Line key={index} direction={event.direction}>
          {event.command ? (
            <Typography component="div" sx={{ fontFamily: MONO, fontSize: 12.5, color: INK }}>
              <Box component="span" sx={{ fontWeight: 700 }}>{event.command}</Box>
              {' '}
              {event.sensitive && event.argument
                ? <Sensitive value={event.argument} />
                : <Box component="span" sx={{ color: INK_SOFT }}>{event.argument}</Box>}
            </Typography>
          ) : (
            <Typography component="div" sx={{ fontFamily: MONO, fontSize: 12.5, color: GREY }}>
              <Box component="span" sx={{ fontWeight: 700, color: INK_SOFT }}>{event.code}</Box>
              {' '}{event.text}
            </Typography>
          )}
        </Line>
      ))}
    </Box>
  );
}

function Summary({ transcript }) {
  const rows = [
    ['Accounts used', (transcript.accounts_used ?? []).join(', ')],
    ['Files transferred', (transcript.files_transferred ?? []).join(', ')],
    ['Senders', (transcript.senders ?? []).join(', ')],
    ['Recipients', (transcript.recipients ?? []).join(', ')],
  ].filter(([, value]) => value);

  if (!rows.length) return null;
  return (
    <Box sx={{ mb: 1.5 }}>
      {rows.map(([label, value]) => (
        <Box key={label} sx={{ display: 'flex', gap: 1.5, fontSize: 12.5, mb: 0.3 }}>
          <Typography sx={{ fontSize: 12.5, color: GREY, width: 130, flexShrink: 0 }}>
            {label}
          </Typography>
          <Typography sx={{ fontSize: 12.5, fontFamily: MONO, color: INK }}>
            {value}
          </Typography>
        </Box>
      ))}
    </Box>
  );
}

function SessionTranscript({ flowId }) {
  const [transcript, setTranscript] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      setTranscript(await getFlowTranscript(flowId));
    } catch (err) {
      // Distinguished rather than collapsed into "something went wrong": a
      // refusal on clearance and a capture that cannot be read call for
      // different actions by the person reading this.
      const detail = err?.response?.data?.detail;
      setError(
        err?.response?.status === 403
          ? (detail || 'Your clearance does not permit reading the contents of a communication.')
          : (detail || 'The conversation could not be rebuilt from the exhibit.'),
      );
    } finally {
      setLoading(false);
    }
  };

  if (!transcript) {
    return (
      <Box sx={{ mt: 1.5 }}>
        <Button
          size="small" variant="outlined" onClick={load} disabled={loading}
          sx={{
            fontSize: 11.5, borderColor: `${CYAN}66`, color: CYAN,
            '&:hover': { borderColor: CYAN, backgroundColor: 'rgba(7,110,124,0.07)' },
          }}
        >
          {loading ? <CircularProgress size={14} sx={{ color: CYAN }} /> : 'Read the conversation'}
        </Button>
        <Typography sx={{ fontSize: 11.5, color: GREY, mt: 0.6 }}>
          Rebuilt from the sealed capture when you ask for it, and recorded in the
          exhibit&rsquo;s chain of custody.
        </Typography>
        {error && <Alert severity="warning" sx={{ mt: 1, fontSize: 12 }}>{error}</Alert>}
      </Box>
    );
  }

  return (
    <Box sx={{ mt: 1.5, p: 2, border: `1px solid ${RULE}`, borderRadius: 1, backgroundColor: PANEL }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.5, flexWrap: 'wrap' }}>
        <Typography sx={{
          fontSize: 11, letterSpacing: 1, fontFamily: MONO, color: GREY,
        }}>
          RECONSTRUCTED CONVERSATION
        </Typography>
        <Chip
          label={(transcript.protocol || 'unknown').toUpperCase()}
          size="small"
          sx={{ height: 18, fontSize: 10, fontFamily: MONO, backgroundColor: PANEL_ALT, color: INK_SOFT }}
        />
        {transcript.credentials_in_the_clear && (
          <Chip
            label="CREDENTIALS SENT IN THE CLEAR"
            size="small"
            sx={{
              height: 18, fontSize: 10, fontWeight: 700,
              backgroundColor: 'rgba(179,38,30,0.12)', color: CRITICAL,
            }}
          />
        )}
      </Box>

      <Caveats transcript={transcript} />

      {!transcript.decoded ? (
        <Typography sx={{ fontSize: 12.5, color: INK_SOFT }}>
          {transcript.reason}
        </Typography>
      ) : (
        <>
          <Summary transcript={transcript} />
          <Exchange transcript={transcript} />
          {transcript.note && (
            <Typography sx={{ fontSize: 11.5, color: GREY, mt: 1 }}>
              {transcript.note}
            </Typography>
          )}
        </>
      )}

      <Typography sx={{ fontSize: 11, color: GREY_MUTED, mt: 1.5 }}>
        Overlapping segments resolved by the <strong>{transcript.reassembly_policy}</strong> policy.
        Protocol identified by port number, which is an inference.
        Exhibit {transcript.exhibit_number}.
      </Typography>
    </Box>
  );
}

export default SessionTranscript;
