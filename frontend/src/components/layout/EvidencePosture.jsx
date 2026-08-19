import { useEffect, useState } from 'react';
import { Box, Typography, Tooltip } from '@mui/material';
import { getEvidencePosture } from '../../services/forensics';
import {
  INK, INK_SOFT, GREY, GREY_MUTED, RULE, PANEL,
  INTACT, MEDIUM, CRITICAL, MONO,
} from '../../theme/tokens';

/**
 * The operator strip: what is being held, and whether it can be relied on.
 *
 * Why this is in the sidebar rather than on a settings page
 * --------------------------------------------------------
 * Four facts change what an officer should do next, and all four are invisible
 * until something has already gone wrong:
 *
 *   the case this work belongs to — because an exhibit with no case reference
 *   is one nobody can find again;
 *
 *   whether the seal still verifies — because a broken seal invalidates
 *   everything downstream of it, and finding out at certificate time is too
 *   late;
 *
 *   whether the clock was network-synchronised — because every timestamp in
 *   the custody log inherits that, and an air-gapped machine's clock is not
 *   synchronised by definition. Saying so is the honest position and it is
 *   also the answer to the first question defence counsel asks about a
 *   timestamp;
 *
 *   whether the evidence store is encrypted — including the case where it is
 *   switched on and some exhibits predate it, which is the failure that looks
 *   like success.
 *
 * Every value is measured on each read, not held as a setting. A strip that
 * reported configuration instead of state would be the wrong thing to put in
 * front of someone all day.
 */

const REFRESH_MS = 60_000;

function Dot({ tone }) {
  const colour = { good: INTACT, warn: MEDIUM, bad: CRITICAL, none: GREY_MUTED }[tone];
  return (
    <Box
      component="span"
      sx={{
        width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
        backgroundColor: colour, mt: '5px',
        // Shape as well as colour, so the state survives a colour-blind
        // reader: anything not "good" carries a ring.
        border: tone === 'good' ? 'none' : `1.5px solid ${colour}`,
        boxSizing: 'content-box',
      }}
    />
  );
}

function Row({ label, value, tone, detail, mono = true }) {
  return (
    <Box sx={{ mb: 1.4 }}>
      <Typography sx={{
        fontSize: 9.5, letterSpacing: 0.9, color: GREY_MUTED, mb: 0.2,
      }}>
        {label}
      </Typography>
      <Box sx={{ display: 'flex', gap: 0.9, alignItems: 'flex-start' }}>
        <Dot tone={tone} />
        <Box sx={{ minWidth: 0 }}>
          <Typography
            title={value}
            sx={{
              fontSize: 11, lineHeight: 1.35, color: INK,
              fontFamily: mono ? MONO : undefined,
              // Breaks at the hyphens an exhibit number already has, rather
              // than splitting a hash-like string at an arbitrary character.
              overflowWrap: 'anywhere',
            }}
          >
            {value}
          </Typography>
          {detail && (
            <Typography sx={{ fontSize: 10, color: GREY, lineHeight: 1.35, mt: 0.2 }}>
              {detail}
            </Typography>
          )}
        </Box>
      </Box>
    </Box>
  );
}

function EvidencePosture({ compact = false }) {
  const [posture, setPosture] = useState(null);

  useEffect(() => {
    let live = true;
    const load = () => getEvidencePosture()
      .then((data) => { if (live) setPosture(data); })
      .catch(() => { /* the strip is context; it must never break the page */ });
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => { live = false; clearInterval(timer); };
  }, []);

  if (!posture) return null;

  const { clock, encryption, exhibits, latest_exhibit: exhibit } = posture;

  const clockTone = {
    synchronised: 'good', unsynchronised: 'warn', unknown: 'warn',
  }[clock?.synchronisation] ?? 'warn';

  const sealTone = !exhibit ? 'none' : (exhibit.seal_intact ? 'good' : 'bad');

  const encryptedAll = encryption?.enabled
    && encryption.exhibits_encrypted === encryption.exhibits_total;
  const encryptionTone = !encryption?.enabled ? 'warn' : (encryptedAll ? 'good' : 'bad');
  const encryptionValue = !encryption?.enabled
    ? 'Stored in the clear'
    : `${encryption.exhibits_encrypted} of ${encryption.exhibits_total} encrypted`;
  const encryptionDetail = !encryption?.enabled
    ? 'Full-disk encryption is the control in force'
    : (encryptedAll ? 'AES-256-GCM' : 'Run encrypt_evidence_store');

  const caseValue = exhibit?.fir_number
    ? `FIR ${exhibit.fir_number}`
    : (exhibit?.case_number || exhibit?.reference_on_exhibit || 'Not recorded');
  const caseDetail = exhibit?.police_station || (
    exhibit?.case_number ? null : 'No case record linked to this exhibit'
  );

  if (compact) {
    // The icon rail. Four dots and a tooltip: the states stay visible on a
    // phone without a 210px column to put words in.
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1.1, py: 1 }}>
        {[
          ['Case', caseValue, 'none'],
          ['Seal', exhibit ? (exhibit.seal_intact ? 'Intact' : 'BROKEN') : '—', sealTone],
          ['Clock', clock?.summary ?? '', clockTone],
          ['Store', encryptionValue, encryptionTone],
        ].map(([label, value, tone]) => (
          <Tooltip key={label} title={`${label}: ${value}`} placement="right">
            <Box sx={{ display: 'flex' }}><Dot tone={tone} /></Box>
          </Tooltip>
        ))}
      </Box>
    );
  }

  return (
    <Box sx={{
      p: 1.4, borderRadius: 1, backgroundColor: PANEL, border: `1px solid ${RULE}`, mb: 1.5,
    }}>
      <Typography sx={{
        fontSize: 9.5, letterSpacing: 1, color: INK_SOFT, fontWeight: 700, mb: 1.2,
      }}>
        EVIDENCE HELD
      </Typography>

      <Row label="CASE" value={caseValue} detail={caseDetail} tone="none" />

      {exhibit && (
        <Row
          label="LATEST EXHIBIT"
          value={exhibit.exhibit_number}
          tone={sealTone}
          detail={exhibit.seal_intact
            ? `Seal verifies · ${exhibit.custody_entries} custody entries`
            : 'SEAL DOES NOT VERIFY'}
        />
      )}

      {exhibit?.is_demonstration_only && (
        <Typography sx={{
          fontSize: 9.5, lineHeight: 1.4, color: CRITICAL, fontWeight: 700,
          border: `1px solid ${CRITICAL}55`, borderRadius: 0.5, p: 0.6, mb: 1.4,
        }}>
          SYNTHETIC — GENERATED TRAFFIC, NOT EVIDENCE
        </Typography>
      )}

      <Row
        label="TIME BASIS"
        value={clockTone === 'good' ? 'Network-synchronised' : 'Not synchronised'}
        tone={clockTone}
        detail={clock?.timezone ? `System zone ${clock.timezone}` : null}
        mono={false}
      />

      <Row
        label="EVIDENCE STORE"
        value={encryptionValue}
        tone={encryptionTone}
        detail={encryptionDetail}
        mono={false}
      />

      {exhibits?.tampered > 0 && (
        <Typography sx={{ fontSize: 10, color: CRITICAL, fontWeight: 700 }}>
          {exhibits.tampered} exhibit(s) failed verification
        </Typography>
      )}
    </Box>
  );
}

export default EvidencePosture;
