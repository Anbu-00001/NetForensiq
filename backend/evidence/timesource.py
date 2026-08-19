"""
What the machine's clock can and cannot be trusted to say.

The question this answers
------------------------
Every timestamp this platform records — when an exhibit was sealed, when an
officer verified a hash, when a certificate was signed — comes from the system
clock of the machine it runs on. On a connected machine that clock is
disciplined by NTP and is right to within milliseconds. On the air-gapped
forensic workstation this platform is built for, there is no NTP, and an
unsynchronised real-time clock drifts by seconds to minutes per month.

So "how do you know your clock was right?" is a fair question and the honest
answer is usually "we do not, precisely". The forensic literature is consistent
on what to do about that: an unverified timestamp is an assertion rather than a
fact, and the accepted practice is to record the clock's state at the time of
examination and disclose it — not to claim an accuracy the hardware cannot
deliver.

This module therefore makes no attempt to correct the clock and never contacts
a time server. It reports what the machine itself can say about its own clock,
so that the answer is on the record rather than reconstructed later.

Deliberately not a security control
-----------------------------------
Everything here comes from the same operating system whose clock is in
question. An administrator who sets the clock back can also make systemd report
whatever they like. This distinguishes an honestly-run air-gapped workstation
from a connected one; it does not distinguish an honest operator from a
dishonest one, and nothing in the output should be read as if it did.
"""

import shutil
import subprocess
from datetime import datetime, timezone

# How the clock stands relative to an external reference.
SYNCHRONISED = 'synchronised'
UNSYNCHRONISED = 'unsynchronised'
UNKNOWN = 'unknown'

# The sentence printed on a certificate for each state. Written out in full
# because this text is read by a court, not by an engineer, and because
# "unsynchronised" alone invites the reader to supply their own meaning.
NOTES = {
    SYNCHRONISED: (
        'The system clock was disciplined by a network time source at the '
        'moment this was recorded. Timestamps are accurate to within the '
        'tolerance of that source.'
    ),
    UNSYNCHRONISED: (
        'The system clock was NOT disciplined by any network time source — '
        'the expected condition on an air-gapped workstation. Timestamps are '
        'taken from the machine\'s own clock, which drifts. They should be '
        'read as recorded by this machine, not as verified absolute time. '
        'Any offset measured against a reference clock should be noted '
        'separately by the examining officer.'
    ),
    UNKNOWN: (
        'The synchronisation state of the system clock could not be '
        'determined on this machine. Timestamps should be read as recorded by '
        'this machine, not as verified absolute time.'
    ),
}

# systemd's own report. Chosen over the kernel's adjtimex flags because it is
# present on every current Linux distribution, needs no privileges, reads
# purely local state, and its field names are stable and documented.
TIMEDATECTL = 'timedatectl'

# `timedatectl show` reads cached state over the system bus and returns in
# milliseconds. The timeout exists only so that a wedged or unresponsive bus
# cannot hang certificate rendering — five seconds is far longer than the call
# can legitimately need, and the timeout path resolves to UNKNOWN, which is the
# truthful answer when the machine will not say.
_QUERY_TIMEOUT_SECONDS = 5


def _read_timedatectl():
    """
    systemd's view of the clock, as a dict, or None if it cannot be obtained.

    Every failure mode — no systemd, a container without a bus, a timeout —
    resolves to None and therefore to UNKNOWN. A module whose job is to be
    candid about uncertainty must not itself become a source of exceptions.
    """
    binary = shutil.which(TIMEDATECTL)
    if not binary:
        return None

    try:
        result = subprocess.run(
            [binary, 'show'], capture_output=True, text=True,
            timeout=_QUERY_TIMEOUT_SECONDS, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None

    fields = {}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition('=')
        if sep:
            fields[key.strip()] = value.strip()
    return fields or None


def describe():
    """
    The clock's state right now, as a plain dict suitable for storing.

    Never raises. `synchronisation` is one of the three constants above and is
    the only field a caller must handle; the rest is detail for the record.
    """
    observed_at = datetime.now(timezone.utc)
    fields = _read_timedatectl()

    if fields is None:
        state = UNKNOWN
        source = 'unavailable'
    else:
        # systemd reports the string 'yes' or 'no'. Anything else — a field
        # that has been renamed, an unexpected value — is treated as unknown
        # rather than guessed at.
        raw = fields.get('NTPSynchronized', '').lower()
        state = {'yes': SYNCHRONISED, 'no': UNSYNCHRONISED}.get(raw, UNKNOWN)
        source = TIMEDATECTL

    return {
        'observed_at': observed_at.isoformat(),
        'synchronisation': state,
        'source': source,
        'timezone': (fields or {}).get('Timezone', ''),
        # Whether the hardware clock is kept in local time rather than UTC. A
        # workstation configured that way will report times that shift by an
        # hour across a daylight-saving boundary, which is worth knowing about
        # an exhibit sealed in March or November.
        'rtc_in_local_time': (fields or {}).get('LocalRTC', '').lower() == 'yes',
        'note': NOTES[state],
    }


def summary_line(state=None):
    """One line for a certificate, a log entry or a status page."""
    state = state or describe()
    label = {
        SYNCHRONISED: 'clock synchronised to a network time source',
        UNSYNCHRONISED: 'clock not network-synchronised (air-gapped or offline)',
        UNKNOWN: 'clock synchronisation state unknown',
    }[state['synchronisation']]

    zone = state.get('timezone')
    return f'{label}; system timezone {zone}' if zone else label
