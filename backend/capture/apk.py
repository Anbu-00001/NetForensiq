"""
Static analysis of an Android package, and correlation of what it contains
with what the network already saw.

Why this sits inside a network forensics platform
=================================================
Because the two halves answer each other. A malicious APK is a claim about
what a device *would* do; a packet capture is a record of what a device *did*.
Separately each is suggestive. Together they are evidence:

    the APK embeds  cdn-analytics.example  ->  and host 10.3.14.101 in
                                               exhibit NF-… resolved and
                                               contacted exactly that name

That correlation is the point of this module. Anyone can run an APK through a
scanner and read a verdict off a screen; nobody can tell a court *why* the
verdict is true. This produces the "why": a named indicator inside the file,
matched against a sealed capture, both of which an examiner can re-derive.

Deliberately no third-party dependencies
========================================
No androguard, no apktool, no VirusTotal lookup. Three reasons, in order of
importance:

1. **The deployment is air-gapped.** A check that needs to phone a cloud
   scanner is a check that fails in the room where it matters, and a verdict
   that arrives from someone else's server is not one this system can explain.
2. **Everything asserted here is re-derivable** from the file itself with the
   Python standard library, so an examiner with the same exhibit and no
   network can reproduce it.
3. Adding a native toolchain to an offline image is how an offline image stops
   installing.

What this does NOT claim
========================
It does not detonate the sample, decompile it, or emulate it. It reads the
manifest, the certificate and the strings in the DEX, and it reports what it
found. A finding here means "this package requests the ability to read your
SMS and contains code that references SmsManager" — never "this is malware,
signed, the machine". The scoring is published, additive and shown with its
own reasons, because a number an officer cannot decompose is a number they
cannot testify to.
"""

import hashlib
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
import bz2
import lzma
import zlib
from collections import OrderedDict

# ── Android binary XML (AXML) ────────────────────────────────────────────────
#
# AndroidManifest.xml inside an APK is not text. It is Android's binary XML:
# a string pool followed by a stream of tag chunks whose attribute values are
# indexes into that pool. The format is stable and documented in AOSP
# (ResourceTypes.h), which is why it can be read here in a few dozen lines
# rather than pulled in as a dependency.

_CHUNK_STRING_POOL = 0x001C0001
_CHUNK_START_TAG = 0x00100102
_CHUNK_END_TAG = 0x00100103

_ATTR_TYPE_STRING = 0x03
_ATTR_TYPE_INT_DEC = 0x10
_ATTR_TYPE_INT_HEX = 0x11
_ATTR_TYPE_BOOL = 0x12




# Magic numbers that tell us a decompression attempt actually worked.
AXML_MAGIC = b'\x03\x00\x08\x00'
DEX_MAGIC = b'dex\n'


def _decompress_every_way(raw):
    """
    Every plausible reading of a ZIP entry's bytes, cheapest first.

    Yields candidates rather than deciding, because the caller knows what the
    decompressed data is supposed to look like and this function does not.
    """
    yield raw                                        # stored
    for attempt in (
        lambda: zlib.decompress(raw, -15),           # raw deflate
        lambda: zlib.decompress(raw),                # zlib-wrapped
        lambda: lzma.decompress(raw),
        lambda: bz2.decompress(raw),
        lambda: zlib.decompressobj(-15).decompress(raw),   # tolerates truncation
    ):
        try:
            out = attempt()
            if out:
                yield out
        except Exception:
            continue


def read_member_raw(path, name, expect=b''):
    """
    Read a ZIP entry by going to its bytes directly, ignoring the header.

    The last resort, and the one that works on samples built to defeat the
    others. A ZIP entry declares its compression method twice — in the central
    directory and in the local file header — and nothing forces the two to
    agree or to be true. Android loads a package by its own rules; a packer
    can therefore write a method field that every general-purpose ZIP library
    refuses while the app still installs and runs.

    That is not hypothetical: it is why `zipfile` and 7-Zip both reported
    "compression method not supported" for a manifest that Android reads
    perfectly well, and why the sample scored as harmless — no readable
    manifest means no permissions, and no permissions looks like innocence.

    So the declared method is ignored. The entry's raw bytes are decompressed
    every way that could apply, and the result is accepted only if it starts
    with the magic number the caller expects. Guessing is safe precisely
    because the answer is checked.
    """
    try:
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo(name)
        header_offset = info.header_offset
        compressed_size = info.compress_size
    except Exception:
        return None

    try:
        with open(path, 'rb') as handle:
            handle.seek(header_offset)
            header = handle.read(30)
            if len(header) < 30 or header[:4] != b'PK\x03\x04':
                return None
            name_len, extra_len = struct.unpack_from('<HH', header, 26)
            handle.seek(name_len + extra_len, os.SEEK_CUR)
            # A zero compressed size means the length lives in a trailing data
            # descriptor; read generously and let the decompressor stop itself.
            raw = handle.read(compressed_size or (1 << 22))
    except Exception:
        return None

    for candidate in _decompress_every_way(raw):
        if not expect or candidate.startswith(expect):
            return candidate
    return None


def _sevenzip():
    """Path to a 7-Zip binary, or None."""
    for name in ('7z', '7za', '7zr'):
        found = shutil.which(name)
        if found:
            return found
    return None


def read_member(archive, name, path, expect=b''):
    """
    Read one entry from an APK, falling back to 7-Zip.

    `zipfile` implements Stored, Deflate, BZip2 and LZMA. It does not
    implement Deflate64, and packers targeting Android use exactly that to
    break naive parsers: the central directory still lists AndroidManifest.xml,
    so a tool reads the file list happily and then fails on the one entry that
    matters. A sample whose manifest cannot be read reports no permissions,
    which reads as harmless — the failure mode flatters the sample.

    So when the standard library refuses an entry, 7-Zip is asked instead,
    and only if that also fails is the entry reported unreadable.
    """
    try:
        return archive.read(name)
    except NotImplementedError:
        pass
    except Exception:
        pass

    binary = _sevenzip()
    if not binary or not path:
        return read_member_raw(path, name, expect) if path else None

    workdir = tempfile.mkdtemp(prefix='netforensiq-7z-')
    try:
        result = subprocess.run(
            [binary, 'e', '-y', f'-o{workdir}', str(path), name],
            capture_output=True, timeout=120,
        )
        target = os.path.join(workdir, os.path.basename(name))
        if result.returncode == 0 and os.path.exists(target):
            with open(target, 'rb') as handle:
                return handle.read()
    except Exception:
        pass
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    # Neither the standard library nor 7-Zip could read it. Go to the bytes.
    return read_member_raw(path, name, expect)


class ManifestUnreadable(Exception):
    """The manifest could not be parsed. Everything else still applies."""


def _read_string_pool(data, offset):
    """Return the list of strings in the pool chunk starting at `offset`."""
    chunk_size, string_count, _style_count, flags, strings_start, _styles_start = (
        struct.unpack_from('<IIIIII', data, offset + 4)
    )
    is_utf8 = bool(flags & 0x0100)
    offsets_at = offset + 28
    base = offset + strings_start

    strings = []
    for i in range(string_count):
        try:
            string_offset = struct.unpack_from('<I', data, offsets_at + i * 4)[0]
            at = base + string_offset
            if is_utf8:
                # UTF-8 pools carry two lengths: characters, then bytes. Both
                # are one byte unless the high bit marks a two-byte length.
                char_len = data[at]
                at += 2 if char_len & 0x80 else 1
                byte_len = data[at]
                if byte_len & 0x80:
                    byte_len = ((byte_len & 0x7F) << 8) | data[at + 1]
                    at += 2
                else:
                    at += 1
                strings.append(data[at:at + byte_len].decode('utf-8', 'replace'))
            else:
                char_len = struct.unpack_from('<H', data, at)[0]
                if char_len & 0x8000:
                    char_len = ((char_len & 0x7FFF) << 16) | struct.unpack_from(
                        '<H', data, at + 2)[0]
                    at += 4
                else:
                    at += 2
                strings.append(
                    data[at:at + char_len * 2].decode('utf-16-le', 'replace'))
        except Exception:
            strings.append('')
    return strings, offset + chunk_size


def parse_android_manifest(data):
    """
    Parse binary AndroidManifest.xml into a list of (tag, {attr: value}).

    Attribute names are returned unqualified ("name", not
    "android:name") because the manifest only ever uses the android namespace
    for the attributes that matter here, and carrying the URI through would
    make every lookup noisier without making any of them safer.
    """
    if len(data) < 8 or struct.unpack_from('<I', data, 0)[0] != 0x00080003:
        raise ManifestUnreadable('not an Android binary XML file')

    strings = []
    offset = 8
    events = []

    while offset + 8 <= len(data):
        chunk_type, chunk_size = struct.unpack_from('<II', data, offset)
        if chunk_size <= 0:
            break

        if chunk_type == _CHUNK_STRING_POOL:
            strings, _ = _read_string_pool(data, offset)

        elif chunk_type == _CHUNK_START_TAG:
            name_index = struct.unpack_from('<I', data, offset + 20)[0]
            attribute_count = struct.unpack_from('<H', data, offset + 28)[0]
            attributes = OrderedDict()
            at = offset + 36
            for _ in range(attribute_count):
                if at + 20 > len(data):
                    break
                _ns, attr_name, raw_value, typed, value = struct.unpack_from(
                    '<IIIII', data, at)
                data_type = (typed >> 24) & 0xFF
                key = strings[attr_name] if attr_name < len(strings) else ''
                if data_type == _ATTR_TYPE_STRING:
                    text = strings[value] if value < len(strings) else ''
                elif data_type == _ATTR_TYPE_BOOL:
                    text = 'true' if value else 'false'
                elif data_type == _ATTR_TYPE_INT_HEX:
                    text = hex(value)
                elif raw_value != 0xFFFFFFFF and raw_value < len(strings):
                    text = strings[raw_value]
                else:
                    text = str(value if value < 0x7FFFFFFF else value - (1 << 32))
                if key:
                    attributes[key] = text
                at += 20
            tag = strings[name_index] if name_index < len(strings) else ''
            events.append((tag, attributes))

        offset += chunk_size

    if not events:
        raise ManifestUnreadable('no elements found')
    return events


# ── Risk model ───────────────────────────────────────────────────────────────
#
# Every weight below is a judgement, so every weight is written down here
# rather than buried in code, and every finding carries the reason it fired.
# The total is additive and capped: an officer must be able to point at a
# score and say which specific observations produced it.

DANGEROUS_PERMISSIONS = {
    'android.permission.READ_SMS': (9, 'Read the contents of SMS messages — the delivery path for one-time banking codes'),
    'android.permission.RECEIVE_SMS': (9, 'Intercept incoming SMS before the user sees them'),
    'android.permission.SEND_SMS': (8, 'Send SMS without the user, at the user\'s cost'),
    'android.permission.READ_CALL_LOG': (6, 'Read who this device has called'),
    'android.permission.RECORD_AUDIO': (8, 'Record from the microphone'),
    'android.permission.CAMERA': (6, 'Capture photographs and video'),
    'android.permission.ACCESS_FINE_LOCATION': (6, 'Track the device\'s precise location'),
    'android.permission.READ_CONTACTS': (6, 'Read the address book'),
    'android.permission.READ_PHONE_STATE': (4, 'Read device identifiers (IMEI, subscriber id)'),
    'android.permission.SYSTEM_ALERT_WINDOW': (8, 'Draw over other apps — the mechanism behind credential overlay attacks'),
    'android.permission.BIND_ACCESSIBILITY_SERVICE': (10, 'Observe and act on everything on screen, in every other app'),
    'android.permission.BIND_DEVICE_ADMIN': (9, 'Device administrator — can lock or wipe, and resists uninstall'),
    'android.permission.REQUEST_INSTALL_PACKAGES': (8, 'Install further packages — the dropper pattern'),
    'android.permission.WRITE_EXTERNAL_STORAGE': (2, 'Write to shared storage'),
    'android.permission.READ_EXTERNAL_STORAGE': (2, 'Read shared storage'),
    'android.permission.RECEIVE_BOOT_COMPLETED': (3, 'Start automatically at boot — persistence'),
    'android.permission.WAKE_LOCK': (1, 'Keep the device awake'),
    'android.permission.INTERNET': (1, 'Open network connections'),
    'android.permission.QUERY_ALL_PACKAGES': (4, 'Enumerate every app installed — target selection'),
    'android.permission.DISABLE_KEYGUARD': (5, 'Dismiss the lock screen'),
    'android.permission.CALL_PHONE': (5, 'Place calls without the user'),
    'android.permission.GET_ACCOUNTS': (4, 'List the accounts configured on the device'),
    'android.permission.PACKAGE_USAGE_STATS': (5, 'See which app is in the foreground — used to time overlays'),
}

# Byte patterns in the DEX. These are references to platform APIs, so their
# presence is a fact about the code, not an inference about intent — which is
# exactly how each is worded.
DEX_INDICATORS = [
    # (pattern, weight, description, corroboration)
    #
    # `corroboration` is the thing that separates a real finding from noise.
    # Almost every modern APK statically links AndroidX, Play Services or the
    # Flutter engine, and those libraries *contain* references to
    # AccessibilityService, DevicePolicyManager and getDeviceId whether or not
    # the app ever calls them. Scoring on the string alone marks every app in
    # the store as stalkerware — which is exactly what the first run of this
    # module did to a benign alarm clock.
    #
    #   None            -> rare enough in libraries that presence is itself
    #                      the finding, and it scores on its own.
    #   'PERMISSION:X'  -> only scores if the manifest also *declares* the
    #                      matching capability. The library can contain the
    #                      code; only the app can ask for the permission.
    (b'Ljava/lang/Runtime;->exec', 7, 'Executes shell commands', None),
    (b'Ldalvik/system/DexClassLoader', 8, 'Loads additional code at runtime — payload is not all in this file', None),
    (b'abortBroadcast', 8, 'Suppresses a system broadcast — hides incoming SMS from other apps', 'PERMISSION:RECEIVE_SMS'),
    (b'Landroid/telephony/SmsManager', 8, 'Sends SMS programmatically', 'PERMISSION:SEND_SMS'),
    (b'/system/bin/su', 8, 'Looks for root access', None),
    (b'AccessibilityService', 8, 'Registers an accessibility service — full screen observation', 'PERMISSION:BIND_ACCESSIBILITY_SERVICE'),
    (b'Landroid/app/admin/DevicePolicyManager', 7, 'Uses device administrator powers', 'PERMISSION:BIND_DEVICE_ADMIN'),
    (b'setComponentEnabledSetting', 6, 'Enables or hides its own components — icon-hiding behaviour', 'NO_LAUNCHER'),
    (b'getSubscriberId', 5, 'Reads the IMSI', 'PERMISSION:READ_PHONE_STATE'),
    (b'getSimSerialNumber', 5, 'Reads the SIM serial', 'PERMISSION:READ_PHONE_STATE'),
    (b'getDeviceId', 5, 'Reads the IMEI', 'PERMISSION:READ_PHONE_STATE'),
    (b'MediaRecorder', 5, 'Records audio or video', 'PERMISSION:RECORD_AUDIO'),
    (b'Ldalvik/system/PathClassLoader', 5, 'Loads code from a path at runtime', 'PERMISSION:REQUEST_INSTALL_PACKAGES'),
    (b'ContactsContract', 4, 'Reads the contacts provider', 'PERMISSION:READ_CONTACTS'),
    (b'Landroid/location/LocationManager', 4, 'Requests device location', 'PERMISSION:ACCESS_FINE_LOCATION'),
    (b'Landroid/content/pm/PackageManager;->getInstalledPackages', 4, 'Enumerates installed applications', 'PERMISSION:QUERY_ALL_PACKAGES'),
    (b'Landroid/util/Base64;->decode', 3, 'Decodes Base64 — commonly wraps an obfuscated payload', 'PERMISSION:INTERNET'),
    (b'Ljavax/crypto/Cipher', 3, 'Encrypts or decrypts data', 'NEVER'),
    (b'TelephonyManager', 3, 'Queries telephony state', 'PERMISSION:READ_PHONE_STATE'),
    (b'Landroid/os/Build;->FINGERPRINT', 3, 'Reads the build fingerprint — often used to detect emulators', 'NEVER'),
]

# Extracted from DEX strings. Deliberately conservative: a pattern that
# matches half the alphabet produces a page of "indicators" that mean nothing.
_URL_RE = re.compile(rb'https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]{4,200}')
_IPV4_RE = re.compile(rb'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
_DOMAIN_RE = re.compile(
    rb'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    rb'(?:com|net|org|info|biz|ru|cn|xyz|tk|onion)\b'
)

# Java/Kotlin package names look exactly like reversed domains, and a DEX is
# full of them. Without this filter the "network indicators" panel fills up
# with androidx.core.app and com.google.android.gms — which are not endpoints
# anything contacted, and which would bury a real C2 domain in noise.
_PACKAGE_PREFIX = re.compile(
    r'^(?:\d+)?(?:androidx|android|kotlin|kotlinx|java|javax|dalvik|sun|libcore|'
    r'com\.google|com\.android|org\.jetbrains|org\.intellij|org\.apache|org\.json|'
    r'org\.w3c|org\.xml|io\.flutter|com\.facebook|com\.squareup|okhttp3|okio|retrofit2)\.',
    re.I,
)
# A DEX string that is a class path, not a host.
_LOOKS_LIKE_CLASS = re.compile(r'(^|\.)(?:[A-Z][A-Za-z0-9]*)$|\$|/|;')

# Hosts belonging to the toolchains that build these apps. Present in almost
# every Flutter or AndroidX build and never an indicator of anything.
_TOOLCHAIN_HOSTS = re.compile(
    r'^(?:docs\.flutter\.dev|flutter\.baseflow\.com|ns\.adobe\.com|goo\.gle|'
    r'pub\.dev|dart\.dev|flutter\.dev|firebase\.google\.com)$', re.I)

# Names that appear in essentially every APK and say nothing about this one.
_DOMAIN_NOISE = re.compile(
    r'(^|\.)(android\.com|google\.com|googleapis\.com|gstatic\.com|schemas\.android\.com|'
    r'w3\.org|apache\.org|json\.org|oracle\.com|sun\.com|github\.com|githubusercontent\.com|'
    r'kotlinlang\.org|jetbrains\.com|mozilla\.org|ietf\.org|xml\.org|bouncycastle\.org|'
    r'example\.com|gradle\.org|maven\.org|slf4j\.org|qos\.ch|unicode\.org|iana\.org)$',
    re.I,
)

# Addresses that cannot be a live C2 and only add noise if reported as one.
_IP_NOISE = re.compile(r'^(0\.|127\.|255\.|1\.0\.0\.[01]$|0\.0\.0\.0$|1\.1\.1\.1$|8\.8\.8\.8$|8\.8\.4\.4$)')


def _has_permission(report, *names):
    permissions = set(report.get('permissions', []))
    return any(f'android.permission.{n}' in permissions or n in permissions
               for n in names)


MAX_SCORE = 100


def _verdict(score, has_manifest):
    """
    Turn the score into words, and keep the words weaker than the number.

    Nothing here says "malware". The tool reports what it observed and how
    strongly; calling it malware is the examiner's conclusion to draw and
    sign for, not a string this function is entitled to print.
    """
    if not has_manifest:
        if score >= 40:
            return ('highly suspicious',
                    'The manifest resisted every decompression method while the '
                    'package remains installable — evasion in itself — and the '
                    'file contents carry further indicators.')
        return ('suspicious — evades inspection',
                'The manifest could not be read by any known method although the '
                'package is installable. Its permissions are therefore hidden, '
                'and treating that as "nothing found" would reward the evasion.')
    if score >= 70:
        return 'highly suspicious', 'Multiple capabilities associated with surveillance or fraud, together in one package.'
    if score >= 40:
        return 'suspicious', 'Several sensitive capabilities that warrant an examiner looking closer.'
    if score >= 15:
        return 'elevated', 'Some sensitive capabilities, which many legitimate apps also request.'
    return 'low', 'Nothing unusual was observed by static inspection.'


def analyse_apk(path, max_dex_bytes=48 * 1024 * 1024):
    """
    Inspect an APK and return a structured report.

    Never raises for a malformed sample: a file that is not a valid APK is a
    finding, not a crash. Anything unreadable is reported as unreadable, and
    the analysis continues over whatever else the file yields.
    """
    report = {
        'is_apk': False, 'manifest_parsed': False,
        'package': '', 'version_name': '', 'version_code': '',
        'min_sdk': '', 'target_sdk': '', 'label': '',
        'debuggable': False, 'allows_cleartext': False,
        'permissions': [], 'permission_findings': [],
        'components': {'activity': [], 'service': [], 'receiver': [], 'provider': []},
        'launcher_activities': [], 'dex_findings': [],
        'urls': [], 'domains': [], 'ips': [],
        'certificate': {}, 'files': {'total': 0, 'dex': 0, 'so': 0, 'assets_apk_or_dex': []},
        'score': 0, 'verdict': 'indeterminate', 'verdict_reason': '',
        'errors': [],
        'sha256': '', 'sha1': '', 'md5': '',
    }

    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            sha256.update(block)
            sha1.update(block)
            md5.update(block)
    report['sha256'] = sha256.hexdigest()
    report['sha1'] = sha1.hexdigest()
    report['md5'] = md5.hexdigest()

    try:
        archive = zipfile.ZipFile(path)
    except Exception as exc:
        report['errors'].append(f'Not a readable ZIP archive: {exc}')
        return report

    with archive:
        names = archive.namelist()
        report['files']['total'] = len(names)
        report['files']['dex'] = sum(1 for n in names if n.endswith('.dex'))
        report['files']['so'] = sum(1 for n in names if n.endswith('.so'))
        # A packed APK or DEX hidden in assets/ is the classic dropper shape:
        # the visible code is a loader and the real payload ships beside it.
        report['files']['assets_apk_or_dex'] = [
            n for n in names
            if n.startswith(('assets/', 'res/raw/')) and n.endswith(('.apk', '.dex', '.jar'))
        ][:20]

        report['is_apk'] = 'AndroidManifest.xml' in names
        if not report['is_apk']:
            report['errors'].append(
                'No AndroidManifest.xml — this ZIP is not an Android package.')

        score = 0
        reasons = []

        # ── manifest ────────────────────────────────────────────────────────
        if report['is_apk']:
            try:
                manifest_bytes = read_member(archive, 'AndroidManifest.xml', path, AXML_MAGIC)
                if manifest_bytes is None:
                    raise ManifestUnreadable(
                        'the entry uses a compression method neither Python nor '
                        '7-Zip could read')
                events = parse_android_manifest(manifest_bytes)
                report['manifest_parsed'] = True

                pending_component = None
                for tag, attrs in events:
                    if tag == 'manifest':
                        report['package'] = attrs.get('package', '')
                        report['version_name'] = attrs.get('versionName', '')
                        report['version_code'] = attrs.get('versionCode', '')
                    elif tag == 'uses-sdk':
                        report['min_sdk'] = attrs.get('minSdkVersion', '')
                        report['target_sdk'] = attrs.get('targetSdkVersion', '')
                    elif tag == 'uses-permission':
                        name = attrs.get('name', '')
                        if name and name not in report['permissions']:
                            report['permissions'].append(name)
                    elif tag == 'application':
                        report['label'] = attrs.get('label', '')
                        report['debuggable'] = attrs.get('debuggable', '') == 'true'
                        report['allows_cleartext'] = (
                            attrs.get('usesCleartextTraffic', '') == 'true')
                    elif tag in ('activity', 'service', 'receiver', 'provider'):
                        name = attrs.get('name', '')
                        if name:
                            report['components'][tag].append(name)
                            pending_component = name
                        # A receiver bound to BIND_DEVICE_ADMIN or an
                        # accessibility service is a capability request that
                        # never appears in <uses-permission>.
                        permission = attrs.get('permission', '')
                        if permission in DANGEROUS_PERMISSIONS and permission not in report['permissions']:
                            report['permissions'].append(permission)
                    elif tag == 'action':
                        name = attrs.get('name', '')
                        if name == 'android.intent.category.LAUNCHER' or name.endswith('.MAIN'):
                            if pending_component:
                                report['launcher_activities'].append(pending_component)
                        if name == 'android.provider.Telephony.SMS_RECEIVED':
                            score += 8
                            reasons.append(('SMS receiver registered', 8,
                                            'Registers to be notified of every incoming SMS'))
                        if name == 'android.intent.action.BOOT_COMPLETED':
                            score += 3
                            reasons.append(('Starts at boot', 3,
                                            'Runs automatically when the device starts'))
            except ManifestUnreadable as exc:
                report['errors'].append(f'AndroidManifest.xml unreadable: {exc}')
            except Exception as exc:
                report['errors'].append(f'AndroidManifest.xml parse failed: {exc}')

        # ── permissions ─────────────────────────────────────────────────────
        for permission in report['permissions']:
            weight, why = DANGEROUS_PERMISSIONS.get(permission, (0, ''))
            if weight:
                score += weight
                report['permission_findings'].append({
                    'permission': permission, 'weight': weight, 'why': why,
                })
        report['permission_findings'].sort(key=lambda f: -f['weight'])

        if report['is_apk'] and not report['manifest_parsed']:
            # This must never read as "nothing found".
            #
            # Android installed and ran this package, so its manifest is
            # well-formed by the only definition that matters. A manifest that
            # the platform reads and every analysis tool refuses is not a
            # damaged file, it is a file built to be unreadable — and the
            # consequence, if it is scored as an absence of evidence, is that
            # the most evasive samples score lowest. That is the failure this
            # branch exists to prevent.
            score += 35
            reasons.append((
                'Manifest is deliberately unreadable', 35,
                'AndroidManifest.xml could not be decompressed by any known '
                'method, yet the package is installable. Malformed ZIP metadata '
                'is a recognised anti-analysis technique, and it hides every '
                'permission this package requests.'))

        if report['debuggable']:
            score += 4
            reasons.append(('Ships debuggable', 4,
                            'Built with debugging enabled, which a release build does not'))
        if report['allows_cleartext']:
            score += 3
            reasons.append(('Permits cleartext traffic', 3,
                            'Explicitly allows unencrypted HTTP'))
        if report['files']['assets_apk_or_dex']:
            score += 8
            reasons.append(('Carries a packaged payload', 8,
                            'An .apk/.dex/.jar bundled in assets — the dropper pattern'))
        if report['is_apk'] and not report['launcher_activities']:
            score += 5
            reasons.append(('No launcher icon', 5,
                            'Declares no launcher activity, so it does not appear in the app drawer'))

        # ── DEX strings ─────────────────────────────────────────────────────
        urls, domains, ips = set(), set(), set()
        seen_indicators = {}
        budget = max_dex_bytes
        for name in names:
            if not name.endswith('.dex') or budget <= 0:
                continue
            blob = read_member(archive, name, path)
            if blob is None:
                report['errors'].append(f'{name} could not be decompressed.')
                continue
            blob = blob[:budget]
            budget -= len(blob)

            for pattern, weight, why, corroboration in DEX_INDICATORS:
                if pattern not in blob or pattern in seen_indicators:
                    continue
                seen_indicators[pattern] = True

                # Does the manifest back this string up? See the note on
                # DEX_INDICATORS: a library can carry the code, but only the
                # application can declare the permission that makes it usable.
                if corroboration is None:
                    corroborated = True
                elif corroboration == 'NEVER':
                    corroborated = False
                elif corroboration == 'NO_LAUNCHER':
                    corroborated = not report['launcher_activities']
                elif corroboration.startswith('PERMISSION:'):
                    corroborated = _has_permission(report, corroboration.split(':', 1)[1])
                else:
                    corroborated = False

                report['dex_findings'].append({
                    'indicator': pattern.decode('utf-8', 'replace'),
                    'weight': weight if corroborated else 0,
                    'why': why,
                    'corroborated': corroborated,
                    'note': '' if corroborated else (
                        'Present in the code but not backed by a declared '
                        'capability — commonly shipped inside a bundled '
                        'library, so it does not score.'),
                })
                if corroborated:
                    score += weight

            for match in _URL_RE.findall(blob)[:4000]:
                urls.add(match.decode('utf-8', 'replace').rstrip('.,);"\''))
            for match in _DOMAIN_RE.findall(blob)[:8000]:
                domains.add(match.decode('utf-8', 'replace').lower())
            for match in _IPV4_RE.findall(blob)[:4000]:
                ips.add(match.decode('utf-8', 'replace'))

        for url in urls:
            host = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0].lower()
            if host and not _DOMAIN_NOISE.search(host):
                domains.add(host)

        report['domains'] = sorted(
            d for d in domains
            if not _DOMAIN_NOISE.search(d)
            and not _PACKAGE_PREFIX.match(d)
            and not _LOOKS_LIKE_CLASS.search(d)
            and not d[0].isdigit()
            and not _TOOLCHAIN_HOSTS.match(d)
        )[:200]
        report['ips'] = sorted(i for i in ips if not _IP_NOISE.match(i))[:200]
        report['urls'] = sorted(u for u in urls
                                if not _DOMAIN_NOISE.search(
                                    re.sub(r'^https?://', '', u).split('/')[0]))[:200]

        report['dex_findings'].sort(key=lambda f: (-f['weight'], f['indicator']))

        # ── signing certificate ─────────────────────────────────────────────
        for name in names:
            upper = name.upper()
            if upper.startswith('META-INF/') and upper.endswith(('.RSA', '.DSA', '.EC')):
                blob = read_member(archive, name, path)
                if blob is None:
                    continue
                report['certificate'] = {
                    'file': name,
                    'sha256': hashlib.sha256(blob).hexdigest(),
                    # The PKCS#7 block is DER; pulling the printable subject
                    # fields out of it is enough to show self-signing without
                    # bringing in an ASN.1 parser.
                    'subject_fragments': sorted({
                        s.decode('utf-8', 'replace')
                        for s in re.findall(rb'[\x20-\x7e]{4,64}', blob)
                        if re.match(rb'^(CN=|O=|OU=|L=|ST=|C=|[A-Za-z ]{4,})$',
                                    s.strip()) and b' ' not in s[:2]
                    })[:12],
                }
                if b'Android Debug' in blob:
                    score += 6
                    reasons.append(('Signed with the Android debug key', 6,
                                    'Signed by the default debug certificate, not a developer key'))
                break
        if report['is_apk'] and not report['certificate']:
            report['errors'].append('No signing block found under META-INF/.')

        report['other_findings'] = [
            {'title': t, 'weight': w, 'why': why} for t, w, why in reasons
        ]
        report['score'] = min(score, MAX_SCORE)
        report['verdict'], report['verdict_reason'] = _verdict(
            report['score'], report['manifest_parsed'])

    return report


# ── correlation with the network evidence ────────────────────────────────────

def correlate_with_captures(report, limit=60):
    """
    Match indicators inside the package against traffic already in evidence.

    This is the part a standalone APK scanner cannot do, and the reason this
    feature belongs here rather than in a separate tool. An indicator that
    only exists inside the file is a capability; the same indicator observed
    in a sealed capture is an event, with a timestamp and an exhibit number
    attached to it.

    Three independent sources are checked, and each match says which one it
    came from so the strength of the claim is visible:

      * **DNS** — a name in the package was actually resolved on the network.
      * **Flow** — an address in the package was actually contacted.
      * **Threat feed** — the indicator is independently listed, by a feed
        whose retrieval date is recorded.
    """
    from .models import DNSRecord, Flow, IOCIndicator

    domains = {d.lower() for d in report.get('domains', [])}
    ips = set(report.get('ips', []))
    matches = []

    if domains:
        rows = (DNSRecord.objects
                .filter(query_name__in=list(domains)[:400])
                .select_related('session', 'session__evidence')[:limit])
        for row in rows:
            session = row.session
            matches.append({
                'kind': 'dns',
                'indicator': row.query_name,
                'detail': f'Resolved by {row.src_ip}',
                'session_id': session.id if session else None,
                'session_name': session.name if session else '',
                'exhibit': (session.evidence.exhibit_number
                            if session and session.evidence else ''),
                'at': row.timestamp.isoformat() if row.timestamp else '',
            })

    if ips:
        rows = (Flow.objects
                .filter(dst_ip__in=list(ips)[:400])
                .select_related('session', 'session__evidence')[:limit])
        for row in rows:
            session = row.session
            matches.append({
                'kind': 'flow',
                'indicator': row.dst_ip,
                'detail': f'Contacted by {row.src_ip} on port {row.dst_port}',
                'session_id': session.id if session else None,
                'session_name': session.name if session else '',
                'exhibit': (session.evidence.exhibit_number
                            if session and session.evidence else ''),
                'at': row.first_seen.isoformat() if row.first_seen else '',
            })

    feed_hits = []
    if domains or ips:
        rows = (IOCIndicator.objects
                .filter(value__in=list(domains | ips)[:600])
                .select_related('feed')[:limit])
        for row in rows:
            feed_hits.append({
                'kind': 'feed',
                'indicator': row.value,
                'detail': f'Listed by {row.feed.name}' if row.feed else 'Listed by a threat feed',
                'session_id': None, 'session_name': '', 'exhibit': '',
                'at': '',
            })

    return {
        'matches': matches[:limit],
        'feed_matches': feed_hits[:limit],
        'checked_domains': len(domains),
        'checked_ips': len(ips),
    }


# ── behavioural classification ───────────────────────────────────────────────
#
# A score says how alarming a sample is. It does not say what the sample *is*,
# and "score 82" is not something an investigating officer can put in a case
# diary. What they need is the shape of the offence: is this stealing one-time
# passwords, watching a spouse, or renting the handset out for ad fraud —
# because those are different sections, different victims and different next
# steps.
#
# So classification is separate from scoring and works differently. Each
# family is defined by the capabilities it *needs* in order to function, split
# into two kinds:
#
#   REQUIRED  — without these the family is not mechanically possible, so a
#               sample missing any of them is never assigned to it.
#   SUPPORTING— consistent with the family and raise confidence, but many
#               legitimate apps have them too.
#
# Confidence is the proportion of required signals present, adjusted by the
# supporting ones, and the matched signals are always returned alongside it.
# A family reported without the evidence that produced it would be exactly the
# unexplainable verdict this module exists to avoid.

def _has_dex(report, *fragments):
    """
    True only for a DEX string the manifest corroborates.

    Uncorroborated strings are still reported to the examiner, but they must
    not drive a family assignment: nearly every APK statically links a library
    that mentions AccessibilityService or DevicePolicyManager, and treating
    that as behaviour classified a benign alarm clock as stalkerware.
    """
    found = {f['indicator'] for f in report.get('dex_findings', [])
             if f.get('corroborated')}
    return any(any(fragment in indicator for indicator in found)
               for fragment in fragments)


def _has_other(report, *titles):
    found = {f['title'] for f in report.get('other_findings', [])}
    return any(t in found for t in titles)


# Each entry: (family, description, what it means for an investigator,
#              [(signal, test)], [(supporting signal, test)])
MALWARE_FAMILIES = [
    (
        'Banking trojan / OTP interceptor',
        'Steals banking credentials and intercepts the one-time passwords sent to confirm transfers.',
        'Treat as financial fraud. The victim\'s bank should be notified — money may move before the handset is examined.',
        [
            ('Can read incoming SMS', lambda r: _has_permission(r, 'READ_SMS', 'RECEIVE_SMS')),
            ('Can present a screen over other apps or observe them',
             lambda r: _has_permission(r, 'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE')
             or _has_dex(r, 'AccessibilityService')),
        ],
        [
            ('Hides incoming SMS from other apps', lambda r: _has_dex(r, 'abortBroadcast')),
            ('Registers for every incoming SMS', lambda r: _has_other(r, 'SMS receiver registered')),
            ('Enumerates installed apps to pick targets',
             lambda r: _has_permission(r, 'QUERY_ALL_PACKAGES') or _has_dex(r, 'getInstalledPackages')),
            ('Sees which app is in the foreground', lambda r: _has_permission(r, 'PACKAGE_USAGE_STATS')),
            ('Contacts a network endpoint', lambda r: bool(r.get('domains') or r.get('ips'))),
        ],
    ),
    (
        'Stalkerware / covert surveillance',
        'Monitors the person holding the device — location, microphone, camera, messages — and reports elsewhere.',
        'Consider an offence against a person rather than property. The installer often has physical access and a personal relationship to the victim.',
        [
            ('Collects personal sensor or message data',
             lambda r: _has_permission(r, 'RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION',
                                       'READ_SMS', 'READ_CONTACTS', 'READ_CALL_LOG')),
            ('Runs without appearing in the app drawer',
             lambda r: _has_other(r, 'No launcher icon') or _has_dex(r, 'setComponentEnabledSetting')),
        ],
        [
            ('Records audio or video', lambda r: _has_dex(r, 'MediaRecorder')),
            ('Requests device location', lambda r: _has_dex(r, 'LocationManager')),
            ('Reads the contacts provider', lambda r: _has_dex(r, 'ContactsContract')),
            ('Restarts itself at boot', lambda r: _has_other(r, 'Starts at boot')),
            ('Exfiltrates to a network endpoint', lambda r: bool(r.get('domains') or r.get('ips'))),
        ],
    ),
    (
        'SMS fraud / premium-rate abuse',
        'Sends messages or subscribes the handset to paid services without the user, billing the victim directly.',
        'The financial loss appears on the victim\'s phone bill. The operator can confirm the destination numbers.',
        [
            ('Can send SMS without the user', lambda r: _has_permission(r, 'SEND_SMS')),
        ],
        [
            ('Sends SMS programmatically', lambda r: _has_dex(r, 'SmsManager')),
            ('Suppresses delivery notifications', lambda r: _has_dex(r, 'abortBroadcast')),
            ('Can place calls', lambda r: _has_permission(r, 'CALL_PHONE')),
            ('No launcher icon', lambda r: _has_other(r, 'No launcher icon')),
        ],
    ),
    (
        'Dropper / stager',
        'Carries or downloads a second payload, so the code that does the harm is not the code being examined.',
        'The sample in hand is not the whole offence. Look for the second stage on the device and in the network capture.',
        [
            ('Loads further code at runtime',
             lambda r: _has_dex(r, 'DexClassLoader', 'PathClassLoader')
             or _has_permission(r, 'REQUEST_INSTALL_PACKAGES')
             or _has_other(r, 'Carries a packaged payload')),
        ],
        [
            ('Bundles an APK/DEX in its assets', lambda r: _has_other(r, 'Carries a packaged payload')),
            ('Can install further packages', lambda r: _has_permission(r, 'REQUEST_INSTALL_PACKAGES')),
            ('Decodes Base64 blobs', lambda r: _has_dex(r, 'Base64')),
            ('Fetches from a network endpoint', lambda r: bool(r.get('urls') or r.get('domains'))),
        ],
    ),
    (
        'Remote access trojan (RAT)',
        'Gives an operator interactive control of the handset — shell commands, file access, live data.',
        'Assume an operator was present and acting. The network capture is the best record of what they did and when.',
        [
            ('Executes commands or seeks root',
             lambda r: _has_dex(r, 'Runtime;->exec', '/system/bin/su')),
            ('Reaches a network endpoint', lambda r: bool(r.get('domains') or r.get('ips') or r.get('urls'))),
        ],
        [
            ('Full screen observation', lambda r: _has_dex(r, 'AccessibilityService')),
            ('Device administrator powers', lambda r: _has_permission(r, 'BIND_DEVICE_ADMIN')),
            ('Reads device identifiers', lambda r: _has_dex(r, 'getDeviceId', 'getSubscriberId')),
            ('Persists across reboots', lambda r: _has_other(r, 'Starts at boot')),
        ],
    ),
    (
        'Device-admin abuse / lockout',
        'Takes administrator rights, which lets it resist removal and lock or wipe the device.',
        'The handset may become unusable during examination. Image it before attempting removal.',
        [
            ('Requests device administrator', lambda r: _has_permission(r, 'BIND_DEVICE_ADMIN')
             or _has_dex(r, 'DevicePolicyManager')),
        ],
        [
            ('Can dismiss the lock screen', lambda r: _has_permission(r, 'DISABLE_KEYGUARD')),
            ('Hides its own icon', lambda r: _has_dex(r, 'setComponentEnabledSetting')),
            ('Encrypts data', lambda r: _has_dex(r, 'Cipher')),
        ],
    ),
]


def classify(report):
    """
    Name the behaviour, with the evidence that names it.

    Returns families sorted by confidence. A sample can legitimately match
    more than one — a banking trojan is usually also a dropper — and reporting
    only the top match would hide half of what the device did.

    A sample matching nothing is reported as matching nothing rather than
    being forced into the nearest family. "Not a family this model describes"
    is a real and frequent answer, and an honest one.
    """
    results = []
    for family, description, guidance, required, supporting in MALWARE_FAMILIES:
        met = [name for name, test in required if _safe(test, report)]
        if len(met) < len(required):
            continue                      # a required capability is absent
        extra = [name for name, test in supporting if _safe(test, report)]

        # Required signals establish the family; supporting ones raise
        # confidence towards, but never to, certainty — static inspection
        # cannot watch the code run.
        confidence = 0.55 + 0.40 * (len(extra) / max(len(supporting), 1))
        results.append({
            'family': family,
            'description': description,
            'investigative_note': guidance,
            'confidence': round(min(confidence, 0.95), 2),
            'required_signals': met,
            'supporting_signals': extra,
        })

    results.sort(key=lambda r: -r['confidence'])
    return results


def _safe(test, report):
    try:
        return bool(test(report))
    except Exception:
        return False
