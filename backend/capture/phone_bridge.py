"""
Getting a capture off a phone.

The question this answers
-------------------------
"Your tool needs a .pcap. Where does a police station get one?" For network
intrusion the answer is a firewall or ISP handoff, but the device a Gujarat
officer actually has in front of them is a phone — a complainant's phone in a
fraud case, or a department handset. This module is about that phone.

Two routes, and the difference matters legally
----------------------------------------------
**Tethering** — the phone shares its connection over USB, and the laptop
captures the traffic passing through its own interface. Nothing is installed on
the phone and the phone is not modified in any way. This is the forensically
safer route and the only one that should go near a device that might be an
exhibit.

**On-device capture** — an app such as PCAPdroid records the traffic on the
phone itself using Android's VpnService, needing no root, and writes a .pcap
which is then copied off. This captures traffic the tether route cannot see
(mobile data when not tethered) but it installs software on the device, which
is the thing ACPO Principle 1 and ordinary Indian seizure practice tell you not
to do to a seized exhibit.

So: tethering for a device in evidence, on-device capture for a consenting
complainant's phone or a department handset. This module supports both and says
which is which, because an officer choosing the wrong one has contaminated an
exhibit and will not find out until cross-examination.

What a capture from a phone actually contains
---------------------------------------------
Metadata, almost entirely. Modern phone traffic is TLS, so what is recoverable
is who was contacted, when, how often, how much data moved, the server name
requested (SNI), and the JA4 fingerprint of the client software — not message
content. That is still enough for the rules this platform runs: beaconing,
covert channels, and volume asymmetry are all timing-and-volume signals. It is
not enough to read anybody's messages, and the interface must not imply it is.
"""

import re
import shutil
import subprocess

# Interface names Linux gives a USB-tethered phone.
#
#   rndis0 / usb0   the classic names
#   enp0s20f0u3     predictable naming — 'u' marks a USB path, which is what
#                   distinguishes a tethered phone from a built-in NIC
TETHER_PATTERNS = (
    re.compile(r'^rndis\d+$'),
    re.compile(r'^usb\d+$'),
    re.compile(r'^en.*u\d+.*$'),
)

_ADB_TIMEOUT = 10


def _run(args, timeout=_ADB_TIMEOUT):
    """Run a command, returning stdout or None. Never raises."""
    binary = shutil.which(args[0])
    if not binary:
        return None
    try:
        result = subprocess.run(
            [binary, *args[1:]], capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def list_interfaces():
    """
    Every interface on this machine, each marked as tethered or not.

    Read from `ip -br link` rather than scapy so it works before any capture is
    attempted and without needing the privileges capture needs.
    """
    output = _run(['ip', '-br', 'link'])
    if output is None:
        return []

    interfaces = []
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0].split('@')[0]
        if name == 'lo':
            continue
        interfaces.append({
            'name': name,
            'state': parts[1] if len(parts) > 1 else 'UNKNOWN',
            'is_tether': any(p.match(name) for p in TETHER_PATTERNS),
            'is_up': len(parts) > 1 and parts[1] == 'UP',
        })
    return interfaces


def find_tethered_interface():
    """
    The interface a tethered phone is on, if exactly one is present.

    Returns (name, explanation). A name of None means the caller must choose —
    never a guess, because capturing the wrong interface records the wrong
    person's traffic, and that is not a recoverable mistake in an investigation.
    """
    interfaces = list_interfaces()
    tethers = [i for i in interfaces if i['is_tether']]

    if not tethers:
        return None, (
            'No USB-tethered device found. On the phone: Settings → Network '
            '& Internet → Hotspot & tethering → USB tethering. An interface '
            'named usb0, rndis0 or en…u… will appear here within a second or '
            'two.'
        )

    live = [i for i in tethers if i['is_up']]
    if len(live) == 1:
        return live[0]['name'], f"Tethered device on {live[0]['name']}."
    if not live:
        names = ', '.join(i['name'] for i in tethers)
        return None, (
            f'Found {names}, but the link is down. Check that USB tethering is '
            f'switched on and that the cable carries data rather than power only.'
        )

    names = ', '.join(i['name'] for i in live)
    return None, (
        f'More than one tethered interface is up ({names}). Name the one to '
        f'capture explicitly — capturing the wrong device records the wrong '
        f'person.'
    )


def adb_devices():
    """
    Phones visible to adb, as a list of (serial, state).

    Used only to give a better message: adb is not needed for tethered capture,
    but if a phone is plugged in and adb can see it while no tether interface
    exists, the useful advice is "turn on USB tethering", not "plug in a phone".
    """
    output = _run(['adb', 'devices'])
    if output is None:
        return []
    devices = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            devices.append((parts[0], parts[1]))
    return devices


def pull_pcapdroid_capture(destination, remote_dir='/sdcard/Download/PCAPdroid'):
    """
    Copy the newest capture PCAPdroid has written, over adb.

    The on-device route. Returns (local_path, explanation); a path of None means
    nothing was copied and the explanation says why.
    """
    devices = [d for d in adb_devices() if d[1] == 'device']
    if not devices:
        unauthorised = [d for d in adb_devices() if d[1] == 'unauthorized']
        if unauthorised:
            return None, (
                'The phone is connected but has not authorised this computer. '
                'Unlock it and accept the "Allow USB debugging" prompt.'
            )
        return None, (
            'No phone visible to adb. Connect it by USB and enable Developer '
            'options → USB debugging.'
        )

    listing = _run(['adb', 'shell', f'ls -t {remote_dir}/*.pcap*'])
    if not listing or not listing.strip():
        return None, (
            f'No capture found in {remote_dir} on the phone. Record one in '
            f'PCAPdroid first (github.com/emanuele-f/PCAPdroid), and set its '
            f'"Dump mode" to "PCAP file".'
        )

    newest = listing.strip().splitlines()[0].strip()
    if _run(['adb', 'pull', newest, str(destination)], timeout=300) is None:
        return None, f'adb could not copy {newest} off the phone.'

    return destination, f'Copied {newest} from the phone.'
