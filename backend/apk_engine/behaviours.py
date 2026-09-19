# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Capabilities (what the code can do) and behaviours (documented combinations).

Two layers, deliberately
========================
**Capabilities** are neutral facts: "calls PackageInstaller.Session.commit",
"routes all traffic into a VPN". Each is found as call sites, string references
or manifest components *belonging to the app or unattributed* — a capability
only a bundled library contains is counted separately and never feeds a
behaviour. Manifest components go through the same split as code (``_manifest``),
because the manifest merger copies an SDK's components into the app's manifest. On their own they
prove nothing: in the evaluation corpus F-Droid and Droid-ify install packages,
and NetGuard, RethinkDNS, AdAway and OpenVPN create VPNs. They are listed
because an examiner needs the inventory, not because they are suspicious.

**Behaviours** are specific combinations of capabilities that published
research or threat reports describe malware using. Each cites that source,
lists the legitimate apps that look similar, and maps to MITRE ATT&CK and —
where one applies — a Google PHA category. None is justified by "we saw it in
one sample"; the install-under-VPN-blackout behaviour is here because CYFIRMA
and Zimperium documented it, not because the judge's dropper does it.

Whether a behaviour may *raise the evidence tier* is not decided here. It is
decided by measurement (baselines.py): a behaviour that fires on any app in the
legitimate corpus is reported as experimental and cannot move the verdict.
"""

from .identity import components_with_action, components_with_permission
from .sources import attack, cite

OVERLAY_WINDOW_TYPES = {2038, 2003, 2006, 2010}   # TYPE_APPLICATION_OVERLAY, SYSTEM_ALERT, SYSTEM_OVERLAY, SYSTEM_ERROR
COMPONENT_ENABLED_STATE_DISABLED = 2
EVIDENCE_SHOWN = 8


class Context:
    def __init__(self, identity, codemap):
        self.identity = identity
        self.codemap = codemap
        self.capabilities = {}


def _api(ctx, owner, method, subclasses=False):
    sites = ctx.codemap.calls(owner, method, include_subclasses=subclasses)
    return ([s for s in sites if s.counts_as_app_code],
            [s for s in sites if not s.counts_as_app_code])


def _strings(ctx, regex):
    sites = ctx.codemap.string_sites(regex)
    return ([s for s in sites if s.counts_as_app_code],
            [s for s in sites if not s.counts_as_app_code])


def _manifest(ctx, names, what):
    """
    Manifest components, split app from library exactly as code evidence is.

    The manifest merger copies an SDK's components into the app's manifest, so
    an accessibility service or SMS receiver declared by a bundled library
    arrives here looking exactly like one the app wrote. Counting those as the
    app's own is the same defect that made the old scorer read NPCI's root check
    as Flipkart's — one layer up, where it can reach a behaviour rule.
    """
    app, library = [], 0
    for name in names:
        if ctx.codemap.attribute_component(name)['kind'] == 'library':
            library += 1
        else:
            app.append({'manifest': what, 'component': name})
    return app, library


ACTION_SET_TEXT = 2097152   # AccessibilityNodeInfo.ACTION_SET_TEXT
OLD_TARGET_SDK = 22         # see _targets_pre_marshmallow

# ── capability detectors: return (app_evidence, library_evidence_count) ─────

def _install_packages(ctx):
    app, lib = _api(ctx, 'Landroid/content/pm/PackageInstaller$Session;', 'commit')
    s_app, s_lib = _strings(ctx, r'^(application/vnd\.android\.package-archive|'
                                 r'android\.intent\.action\.INSTALL_PACKAGE)$')
    return app + s_app, len(lib) + len(s_lib)


def _vpn_interface(ctx):
    app, lib = _api(ctx, 'Landroid/net/VpnService$Builder;', 'establish')
    return app, len(lib)


def _vpn_catch_all(ctx):
    app, lib = _api(ctx, 'Landroid/net/VpnService$Builder;', 'addRoute')
    evidence = []
    for site in app:
        routes = [args for args in site.constant_arguments('addRoute')
                  if len(args) >= 2 and args[0] in ('0.0.0.0', '::') and args[1] == 0]
        if routes:
            item = site.evidence()
            item['routes'] = [f'{a[0]}/{a[1]}' for a in routes]
            evidence.append(item)
    return evidence, len(lib)


def _sms_send(ctx):
    evidence, lib = [], 0
    for method in ('sendTextMessage', 'sendMultipartTextMessage', 'sendDataMessage'):
        app, l = _api(ctx, 'Landroid/telephony/SmsManager;', method)
        evidence += app
        lib += len(l)
    return evidence, lib


def _sms_read(ctx):
    evidence, lib = [], 0
    for method in ('getMessageBody', 'getDisplayMessageBody'):
        app, l = _api(ctx, 'Landroid/telephony/SmsMessage;', method)
        evidence += app
        lib += len(l)
    s_app, s_lib = _strings(ctx, r'^content://sms(/|$)')
    return evidence + s_app, lib + len(s_lib)


def _sms_receiver(ctx):
    names = []
    for action in ('android.provider.Telephony.SMS_RECEIVED', 'android.provider.Telephony.SMS_DELIVER'):
        names += components_with_action(ctx.identity, action)
    return _manifest(ctx, sorted(set(names)), 'receiver for incoming SMS')


def _accessibility_service(ctx):
    names = components_with_permission(ctx.identity, 'android.permission.BIND_ACCESSIBILITY_SERVICE', ('service',))
    return _manifest(ctx, names, 'accessibility service')


def _accessibility_actions(ctx):
    evidence, lib = [], 0
    for owner, method, sub in (
            ('Landroid/accessibilityservice/AccessibilityService;', 'performGlobalAction', True),
            ('Landroid/accessibilityservice/AccessibilityService;', 'dispatchGesture', True),
            ('Landroid/view/accessibility/AccessibilityNodeInfo;', 'performAction', False)):
        app, l = _api(ctx, owner, method, subclasses=sub)
        evidence += app
        lib += len(l)
    return evidence, lib


def _overlay_window(ctx):
    """
    Windows drawn over other apps.

    The window type reaches LayoutParams either as a constructor argument or,
    more often, by assignment to its ``type`` field — so looking only at
    constructor arguments found nothing at all, in 31 legitimate apps and in
    the malicious one. What is checked instead is whether a method that touches
    LayoutParams or adds a view also loads one of the overlay type constants.
    """
    evidence, lib = [], 0
    seen = set()
    for owner, method in (('Landroid/view/WindowManager$LayoutParams;', '<init>'),
                          ('Landroid/view/WindowManager;', 'addView'),
                          ('Landroid/view/ViewManager;', 'addView')):
        app, others = _api(ctx, owner, method)
        lib += len(others)
        for site in app:
            key = (site.caller_class, str(site.caller_method.name))
            if key in seen:
                continue
            if site.constant_values() & OVERLAY_WINDOW_TYPES:
                seen.add(key)
                evidence.append(site)
    return evidence, lib


def _accessibility_text_entry(ctx):
    """
    Typing into another app through accessibility, not merely tapping.

    Herodotus splits the operator's text "into chars, and they are separately
    set with random delays" through ``ACTION_SET_TEXT`` to defeat behavioural
    biometrics; PixRevolution uses ``performAction(ACTION_SET_TEXT)`` to
    overwrite the focused field. Entering text is a narrower act than the
    gestures ``cap.accessibility_actions`` already counts, which is the point:
    the broader capability fires on legitimate automation tools.
    """
    evidence, lib = [], 0
    for owner, method in (('Landroid/view/accessibility/AccessibilityNodeInfo;', 'performAction'),
                          ('Landroid/app/UiAutomation;', 'performGlobalAction')):
        app, others = _api(ctx, owner, method)
        lib += len(others)
        for site in app:
            if ACTION_SET_TEXT in site.constant_values():
                evidence.append(site)
    return evidence, lib


def _screen_capture(ctx):
    """Capturing the screen through MediaProjection."""
    evidence, lib = [], 0
    for owner, method in (
            ('Landroid/media/projection/MediaProjectionManager;', 'createScreenCaptureIntent'),
            ('Landroid/media/projection/MediaProjection;', 'createVirtualDisplay')):
        app, others = _api(ctx, owner, method)
        evidence += app
        lib += len(others)
    return evidence, lib


def _bundled_package(ctx):
    """
    Another installable package carried inside this one.

    A dropper has to put its second stage somewhere. ThreatFabric documented
    SecuriDropper installing that stage through the session API so the system
    "cannot differentiate between an application installed by a dropper and a
    marketplace"; the payload itself still has to be present or fetched.
    """
    names = ctx.identity.get('bundled_packages') or []
    return _manifest(ctx, names, 'package file carried inside this one')[0], 0


def _targets_pre_marshmallow(ctx):
    """
    targetSdkVersion 22 or lower — below the runtime permission model.

    Google states that "over 95% of spyware we detect outside of the Play Store
    intentionally targets API level 22 or lower, avoiding runtime permissions
    even when installed on recent Android versions". Android 14 refuses to
    install such packages at all, so this is now evidence about an older sample
    rather than a working technique, and it is reported as a capability, never
    as harm on its own.
    """
    target = ctx.identity.get('target_sdk')
    if target is None or target > OLD_TARGET_SDK:
        return [], 0
    return [{'manifest': 'targetSdkVersion', 'component': str(target)}], 0


def _network_use(ctx):
    """
    Hands something to a networking API from the package's own code.

    Deliberately broad — almost every app talks to the network — so this is a
    conjunct, never a finding. It exists so that rules like "loads code at
    runtime AND reaches the network" can say the second half.
    """
    from .codemap import NETWORK_APIS
    evidence, lib = [], 0
    for owner, method in NETWORK_APIS:
        app, others = _api(ctx, owner, method)
        evidence += app
        lib += len(others)
    return evidence[:EVIDENCE_SHOWN], lib


def _device_admin(ctx):
    names = components_with_permission(ctx.identity, 'android.permission.BIND_DEVICE_ADMIN', ('receiver',))
    evidence, lib = _manifest(ctx, names, 'device administrator receiver')
    for method in ('lockNow', 'wipeData', 'resetPassword'):
        app, l = _api(ctx, 'Landroid/app/admin/DevicePolicyManager;', method)
        evidence += app
        lib += len(l)
    return evidence, lib


def _shell_exec(ctx):
    app, lib = _api(ctx, 'Ljava/lang/Runtime;', 'exec')
    app2, lib2 = _api(ctx, 'Ljava/lang/ProcessBuilder;', 'start')
    return app + app2, len(lib) + len(lib2)


def _dynamic_code(ctx):
    evidence, lib = [], 0
    for owner in ('Ldalvik/system/DexClassLoader;', 'Ldalvik/system/InMemoryDexClassLoader;'):
        app, l = _api(ctx, owner, '<init>')
        evidence += app
        lib += len(l)
    return evidence, lib


def _root_detection_strings(ctx):
    app, lib = _strings(ctx, r'^/(system/(x?bin|sd/xbin|bin/failsafe)|sbin|data/local(/x?bin)?|su/bin)/su$')
    return app, len(lib)


def _notification_listener(ctx):
    names = components_with_permission(ctx.identity, 'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE', ('service',))
    return _manifest(ctx, names, 'notification listener')


def _boot_start(ctx):
    names = components_with_action(ctx.identity, 'android.intent.action.BOOT_COMPLETED')
    return _manifest(ctx, names, 'receiver started at boot')


def _hides_launcher_icon(ctx):
    launchers = ctx.identity.get('launcher_activities') or []
    if not launchers:
        return [], 0
    package = ctx.identity.get('package') or ''
    names = set()
    for name in launchers:
        full = package + name if name.startswith('.') else name
        names |= {full, 'L' + full.replace('.', '/') + ';'}
    app, lib = _api(ctx, 'Landroid/content/pm/PackageManager;', 'setComponentEnabledSetting')
    evidence = []
    for site in app:
        disables = any(len(args) >= 2 and args[1] == COMPONENT_ENABLED_STATE_DISABLED
                       for args in site.constant_arguments('setComponentEnabledSetting'))
        if disables and site.references(*names):
            evidence.append(site)
    return evidence, len(lib)


def _telegram_bot_api(ctx):
    app, lib = _strings(ctx, r'api\.telegram\.org/bot')
    return app, len(lib)


def _quick_tunnel_url(ctx):
    app, lib = _strings(ctx, r'[a-z0-9-]+\.trycloudflare\.com')
    return app, len(lib)


def _query_installed_apps(ctx):
    evidence, lib = [], 0
    for method in ('getInstalledPackages', 'getInstalledApplications'):
        app, l = _api(ctx, 'Landroid/content/pm/PackageManager;', method)
        evidence += app
        lib += len(l)
    return evidence, lib


def _contactless_card_read(ctx):
    """
    Exchanges APDUs with an ISO 14443-4 card through IsoDep.

    IsoDep is the contactless smartcard technology — payment cards, transit
    cards, identity documents. Plain NFC tags go through Ndef or NfcA, so an app
    calling IsoDep.transceive is talking to a card rather than reading a sticker.
    CERT Polska's analysis of NGate: "the phone behaves as a reader to a real
    card tapped by the victim".
    """
    return _api(ctx, 'Landroid/nfc/tech/IsoDep;', 'transceive')


# See _minimal_permission_set. The one fitted number in the NFC relay rule.
MINIMAL_PERMISSIONS = 10


def _minimal_permission_set(ctx):
    """
    Declares MINIMAL_PERMISSIONS or fewer permissions in total.

    Neutral on its own — most small utilities qualify. It exists for one rule.
    Cleafy describes SuperCard X's "focused functionality and consequent
    minimalistic permission model", declaring "only the essential
    android.permission.NFC permission"; CERT Polska found NGate declaring NFC,
    INTERNET and ACCESS_NETWORK_STATE. A relay needs nothing else, and needing
    nothing else is also how it avoids every permission-based check.

    **The threshold is fitted, and says so.** In the design corpus the 24 relay
    samples declared 4 to 9 permissions; the only legitimate app that both reads
    contactless cards and uses the network — Swiss Bitcoin Pay, a payment
    terminal — declares 17. Ten sits between them with room on the malicious
    side, but it was chosen with both numbers in view, and a held-out set is what
    tests whether it generalises.
    """
    declared = ctx.identity.get('permissions') or []
    if not declared or len(declared) > MINIMAL_PERMISSIONS:
        return [], 0
    return [{'manifest': 'uses-permission', 'component': f'{len(declared)} declared in total'}], 0


# A DEX this small cannot hold an app's logic; it can hold a loader.
STUB_DEX_MAX_BYTES = 100_000


def _encrypted_code_payload(ctx):
    """
    A stub-sized DEX beside a large entry that is statistically random.

    The packing layout: a small loader in classes.dex whose job is to decrypt
    the real code from somewhere else in the package at runtime. Zimperium on
    Konfety: code "loaded at runtime from an encrypted asset bundled within the
    APK. This encrypted file contains a secondary DEX". Duan et al. (NDSS 2018,
    p.3): a packed app "packs its Java code as well as its native code ... into
    binary resource files" and "still maintains a dummy Java component, which
    acts solely as a dispatcher to launch the unpacking procedure".

    What it proves is that the code the engine examined is not the code that
    runs — evasion, not harm. Duan et al. also found that "both legitimate and
    malicious apps are leveraging packing mechanisms", and commercially packed
    legitimate apps are under-represented in an F-Droid corpus, where nothing is
    packed. See frameworks.opaque_payloads for the measurement.
    """
    dex_bytes = getattr(ctx.codemap, 'dex_bytes', None)
    blobs = ctx.identity.get('opaque_payloads') or []
    if dex_bytes is None or dex_bytes >= STUB_DEX_MAX_BYTES or not blobs:
        return [], 0
    return [{'manifest': 'package entry',
             'component': f"{b['name']} ({b['size']:,} bytes, entropy {b['entropy']}) "
                           f"beside {dex_bytes:,} bytes of DEX"} for b in blobs[:3]], 0


CAPABILITIES = [
    # (id, title, detector)
    ('cap.install_packages', 'Installs other packages', _install_packages),
    ('cap.vpn_interface', 'Creates a VPN interface', _vpn_interface),
    ('cap.vpn_catch_all_route', 'Routes all traffic (0.0.0.0/0 or ::/0) into its VPN', _vpn_catch_all),
    ('cap.sms_send', 'Sends SMS programmatically', _sms_send),
    ('cap.sms_read', 'Reads SMS message contents', _sms_read),
    ('cap.sms_receiver', 'Registered to receive incoming SMS', _sms_receiver),
    ('cap.accessibility_service', 'Declares an accessibility service', _accessibility_service),
    ('cap.accessibility_actions', 'Performs actions through accessibility APIs', _accessibility_actions),
    ('cap.overlay_window', 'Creates windows drawn over other apps', _overlay_window),
    ('cap.device_admin', 'Uses device administrator powers', _device_admin),
    ('cap.shell_exec', 'Executes shell commands', _shell_exec),
    ('cap.dynamic_code_loading', 'Loads DEX code at runtime', _dynamic_code),
    ('cap.root_detection_strings', 'Contains su-binary paths (root detection or rooting)', _root_detection_strings),
    ('cap.notification_listener', 'Reads notifications of other apps', _notification_listener),
    ('cap.boot_start', 'Starts when the device boots', _boot_start),
    ('cap.hides_launcher_icon', 'Disables its own launcher entry', _hides_launcher_icon),
    ('cap.telegram_bot_api', 'Contains a Telegram Bot API endpoint', _telegram_bot_api),
    ('cap.quick_tunnel_url', 'Contains a Cloudflare quick-tunnel URL', _quick_tunnel_url),
    ('cap.query_installed_apps', 'Lists installed applications', _query_installed_apps),
    ('cap.accessibility_text_entry', 'Enters text into other apps through accessibility',
     _accessibility_text_entry),
    ('cap.screen_capture', 'Captures the screen through MediaProjection', _screen_capture),
    ('cap.bundled_package', 'Carries a nested package or DEX payload in its assets', _bundled_package),
    ('cap.targets_pre_marshmallow', 'Targets API 22 or lower, below the runtime permission model',
     _targets_pre_marshmallow),
    ('cap.network_use', 'Uses networking APIs from its own code', _network_use),
    ('cap.contactless_card_read', 'Exchanges APDUs with a contactless card (IsoDep)',
     _contactless_card_read),
    ('cap.minimal_permission_set', f'Declares {MINIMAL_PERMISSIONS} or fewer permissions',
     _minimal_permission_set),
    ('cap.encrypted_code_payload', 'Stub-sized DEX beside a large statistically random entry',
     _encrypted_code_payload),
]


def detect_capabilities(identity, codemap):
    ctx = Context(identity, codemap)
    results = []
    for cap_id, title, detector in CAPABILITIES:
        try:
            items, library_count = detector(ctx)
            error = ''
        except Exception as exc:          # one broken detector must not hide the rest
            items, library_count, error = [], 0, str(exc)
        # Evidence — including the call-path search — is built only for what is
        # shown. A large app can call an API hundreds of times.
        evidence = [i if isinstance(i, dict) else i.evidence() for i in items[:EVIDENCE_SHOWN]]
        ctx.capabilities[cap_id] = evidence
        results.append({
            'id': cap_id, 'title': title,
            'present': bool(items),
            'evidence': evidence, 'evidence_total': len(items),
            'library_only_occurrences': library_count,
            'error': error,
        })
    return ctx, results


# ── behaviours ─────────────────────────────────────────────────────────────

BEHAVIOURS = [
    # Added 19 Sep 2026 from families measured in our own MalwareBazaar corpus.
    # Every source below was re-opened by an audit pass before being cited.
    # None of these can raise a tier until baselines.py has measured it against
    # the legitimate corpus — that gate is the whole design, and new rules are
    # not exempt from it.
    {
        'id': 'beh.dropper_with_bundled_payload',
        'title': 'Installs packages and carries its own payload to install',
        'description': (
            'The code installs packages and the package itself carries a nested archive or DEX '
            'in its assets. ThreatFabric documented SecuriDropper installing its second stage '
            'through the session API so that "the Operating System cannot differentiate between '
            'an application installed by a dropper and a marketplace", which is how Android 13 '
            'restricted settings are bypassed.'),
        'requires': ('cap.install_packages', 'cap.bundled_package'),
        'tier': 3,
        'pha': 'hostile-downloader',
        'attack': ('T1407',),
        'sources': ('threatfabric-securidropper-2023',),
        'lookalikes': ('App stores install packages, and some ship a bundled helper or a test '
                       'fixture. An installer whose payload travels inside it is the dropper '
                       'pattern; an installer that downloads from its own store is not.'),
    },
    {
        'id': 'beh.runtime_code_from_network',
        'title': 'Loads code at runtime and talks to the network from its own code',
        'description': (
            'The code loads DEX at runtime and also contains its own network endpoints. Google '
            'forbids this for Play-distributed apps — "an app may not download executable code '
            '(such as dex, JAR, .so files) from a source other than Google Play" — so it is a '
            'policy violation for the legitimate population, and it is how staged payloads '
            'arrive: SpyNote fetches encrypted modules at runtime and decrypts them in memory.'),
        'requires': ('cap.dynamic_code_loading', 'cap.network_use'),
        'tier': 3,
        'pha': 'hostile-downloader',
        'attack': ('T1407',),
        'sources': ('android-dcl-policy', 'cyfirma-spynote-2024'),
        'lookalikes': ('Plugin frameworks, some app stores and a few legitimate SDKs load code '
                       'at runtime. Measured on 299 unseen legitimate apps, one did.'),
    },
    {
        'id': 'beh.accessibility_types_into_other_apps',
        'title': 'Types into other apps through accessibility while drawing over them',
        'description': (
            'The code enters text into other applications through accessibility and also draws '
            'windows over them. ThreatFabric records Herodotus splitting the operator\'s text '
            '"into chars, and they are separately set with random delays" through ACTION_SET_TEXT '
            'to defeat behavioural biometrics; Zimperium records PixRevolution using '
            'performAction(ACTION_SET_TEXT) to overwrite a focused payment field behind a '
            'full-screen overlay.'),
        'requires': ('cap.accessibility_text_entry', 'cap.overlay_window'),
        'tier': 3,
        'pha': 'spyware',
        'attack': ('T1417.002', 'T1516'),
        'sources': ('threatfabric-herodotus-2025', 'zimperium-pixrevolution-2026'),
        'lookalikes': ('Password managers fill fields through accessibility, and launchers draw '
                       'overlays. Entering text into another app while covering it is the '
                       'device-takeover pattern.'),
    },
    {
        'id': 'beh.screen_capture_to_network',
        'title': 'Captures the screen and sends it off the device',
        'description': (
            'The code captures the screen through MediaProjection and contains its own network '
            'endpoints. Zimperium records PixRevolution creating a virtual display and streaming '
            'it to a C2 over a persistent TCP connection while an operator watches.'),
        'requires': ('cap.screen_capture', 'cap.network_use'),
        'tier': 3,
        'pha': 'spyware',
        'attack': ('T1513',),
        'sources': ('zimperium-pixrevolution-2026',),
        'lookalikes': ('Screen recorders, casting and remote-support tools capture the screen '
                       'legitimately; most keep the recording on the device.'),
    },
    {
        'id': 'beh.adb_payload_dropper',
        'title': 'Installs packages and runs shell commands, persisting across reboot',
        'description': (
            'The code installs packages, executes shell commands and registers to start at boot. '
            'This is the Android TV-box botnet profile rather than phone spyware: Comcast '
            'documented JackSkid dropping payloads over ADB with native libraries named to '
            'imitate system components, and Rescana documented Kimwolf spreading to devices with '
            'ADB exposed on TCP/5555 as both APK and ELF.'),
        'requires': ('cap.install_packages', 'cap.shell_exec', 'cap.boot_start'),
        'tier': 3,
        'pha': 'hostile-downloader',
        'attack': ('T1407',),
        'sources': ('comcast-jackskid-2026', 'rescana-kimwolf-2026'),
        # Measured 19 Sep 2026 against 201 F-Droid apps: fired on 4 legitimate apps
        # (including K-9 Mail and AdAway) and 3 of 194 malicious. The conjunction is
        # far less specific than the botnets it cites — those are defined by ADB on
        # TCP/5555 and ELF payloads, which none of these three capabilities captures.
        # The engine keeps it experimental, so it cannot raise a tier; the text below
        # says what was measured rather than what was assumed when it was written.
        'lookalikes': ('Terminal emulators run shell commands, app stores install packages and '
                       'many apps start at boot — and some legitimate apps do all three: this '
                       'fired on 4 of 201 F-Droid apps, including K-9 Mail and AdAway. It is '
                       'context for an examiner, not evidence on its own.'),
    },
    {
        'id': 'beh.install_under_network_blackout',
        'title': 'Installs a package while forcing all traffic into its own VPN',
        'description': (
            'The code installs other packages and also creates a VPN that captures every '
            'route. Documented in Indian RTO-challan droppers, where the VPN is used to '
            '"block or control Internet traffic" during installation, and in ToxicPanda, '
            'which blocks Google Play and Play Protect before installing its payload.'),
        'requires': ('cap.install_packages', 'cap.vpn_catch_all_route'),
        'tier': 3,
        'pha': 'hostile-downloader',
        'attack': ('T1407', 'T1629.003'),
        'sources': ('cyfirma-2025-rto', 'toxicpanda-2026'),
        'lookalikes': ('App stores and updaters install packages; firewalls, ad blockers and '
                       'VPN clients route all traffic into a VPN. Neither kind does both.'),
    },
    {
        'id': 'beh.install_from_quick_tunnel',
        'title': 'Installs packages and embeds a Cloudflare quick-tunnel address',
        'description': (
            'Quick tunnels need no account and are torn down at will — temporary '
            'infrastructure that static blocklists cannot keep up with, which is why '
            'they are abused for payload delivery. Combined with the ability to '
            'install packages, the tunnel is a plausible payload source.'),
        'requires': ('cap.install_packages', 'cap.quick_tunnel_url'),
        'tier': 3,
        'pha': 'hostile-downloader',
        'attack': ('T1407',),
        'sources': ('proofpoint-2024-trycloudflare',),
        'lookalikes': 'Developers use quick tunnels while testing; a shipped build rarely should.',
    },
    {
        'id': 'beh.sms_to_telegram_bot',
        'title': 'Receives or reads SMS and embeds a Telegram Bot API endpoint',
        'description': (
            'Tria stealer registers SMS receivers and sends message contents to attacker '
            'bots through the Bot API\'s sendMessage method; TeleRAT hard-codes bot tokens '
            'and exfiltrates through the same API, which avoids any attacker-owned server.'),
        'requires_any': (('cap.sms_receiver', 'cap.sms_read'),),
        'requires': ('cap.telegram_bot_api',),
        'tier': 3,
        'pha': 'spyware',
        'attack': ('T1636.004', 'T1481.003'),
        'sources': ('securelist-2025-tria', 'unit42-2018-telerat', 'telegram-bot-api'),
        'lookalikes': ('Telegram clients use MTProto, not the Bot API endpoint; SMS apps have no '
                       'reason to address a bot.'),
    },
    {
        'id': 'beh.hides_launcher_icon',
        'title': 'Disables its own launcher entry',
        'description': ('Code disables the component that gives the app its launcher icon, so it '
                        'keeps running without appearing in the app drawer.'),
        'requires': ('cap.hides_launcher_icon',),
        'tier': 2,
        'pha': None,
        'attack': ('T1628.001',),
        'sources': ('mitre-attack-mobile',),
        'lookalikes': 'Apps offering a user-chosen "hide app" or alternate-icon feature.',
    },
    {
        'id': 'beh.accessibility_control_with_overlay',
        'title': 'Drives other apps through accessibility while drawing over them',
        'description': ('An accessibility service that performs actions, combined with windows '
                        'drawn over other apps, gives complete control of the UI feedback loop — '
                        'the capability banking trojans use to capture input and act for the user.'),
        'requires': ('cap.accessibility_service', 'cap.accessibility_actions', 'cap.overlay_window'),
        'tier': 3,
        'pha': None,
        'attack': ('T1516', 'T1417.002'),
        'sources': ('cloak-and-dagger-2017', 'toxicpanda-2026'),
        'lookalikes': 'Automation and assistive apps combine the same APIs legitimately.',
    },
    # Added 19 Sep 2026. Both were measured on the design corpus before being
    # written (research/154 §8): the relay rule matched 24 of 200 malicious
    # samples, every one of them previously missed, and 0 of 300 F-Droid apps;
    # the packing rule matched 38 and 0. Neither becomes evidence until the
    # re-baseline validates it, and neither is claimed as a detection rate until
    # the held-out corpus has been run.
    {
        'id': 'beh.nfc_card_relay',
        'title': 'Reads contactless payment cards and relays them over the network',
        'description': (
            'The code exchanges APDUs with a contactless card through IsoDep, talks to the '
            'network, and asks for almost nothing else. That is the NFC relay profile: the '
            'victim taps their own card against their own phone and the malware forwards the '
            'exchange to an attacker holding a second device at an ATM or payment terminal. '
            'ESET documented NGate doing this with code from the NFCGate research tool; CERT '
            'Polska found it relaying EMV data over a plain framed TCP protocol; Cleafy found '
            'SuperCard X doing it over mTLS with a "minimalistic permission model" that avoids '
            'the checks banking trojans trip. The transport varies between families, which is '
            'why this requires network use rather than any one protocol.'),
        'requires': ('cap.contactless_card_read', 'cap.network_use', 'cap.minimal_permission_set'),
        'tier': 3,
        'pha': 'spyware',
        'attack': ('T1646',),
        'sources': ('certpl-ngate-2025', 'cleafy-supercardx-2025'),
        'lookalikes': ('Payment terminals, transit-card readers and identity-document scanners '
                       'read contactless cards legitimately, and some use the network. The one '
                       'such app in the evaluation corpus (a Bitcoin payment terminal) declares '
                       '17 permissions; the relay samples declared 4 to 9. The permission '
                       'threshold is what separates them, and it is the rule\'s weakest part.'),
    },
    {
        'id': 'beh.packed_code_payload',
        'title': 'Hides its code: a loader stub beside an encrypted payload',
        'description': (
            'The DEX is too small to be the application and sits beside a large entry whose '
            'bytes are statistically random. That is the layout of a packer: the examined code '
            'is a loader, and the code that runs is decrypted from the payload at runtime. '
            'Zimperium documented Konfety loading "additional executable code ... at runtime '
            'from an encrypted asset bundled within the APK"; Duan et al. describe a packed app '
            'keeping "a dummy Java component, which acts solely as a dispatcher to launch the '
            'unpacking procedure".'),
        'requires': ('cap.encrypted_code_payload',),
        # Tier 2 and no PHA category: this is evidence that the package conceals what it
        # does from analysis, the same claim the integrity indicators make. It is not
        # evidence of what the concealed code does.
        'tier': 2,
        'pha': None,
        'attack': ('T1406',),
        'sources': ('zimperium-konfety-2025', 'duan-ndss-2018'),
        'lookalikes': ('Commercially packed legitimate apps — banking apps in particular — share '
                       'this layout. Duan et al. found commercial packers "widely used by many '
                       'developers to pack and protect their intellectual property", and the F-Droid corpus this was measured on contains no packed '
                       'apps at all, so its zero benign firings overstate how clean this is. The first '
                       'held-out test found two more lookalikes — a speech engine beside a ZIP of voice '
                       'data and an instrument app beside a PNG — both native-code apps with a thin Java '
                       'layer; payloads in a recognised format (ZIP, PNG, audio, fonts) are now excluded.'),
    },
]


def detect_behaviours(ctx):
    findings = []
    for rule in BEHAVIOURS:
        caps = ctx.capabilities
        if not all(caps.get(c) for c in rule['requires']):
            continue
        if not all(any(caps.get(c) for c in group) for group in rule.get('requires_any', ())):
            continue
        used = list(rule['requires']) + [c for g in rule.get('requires_any', ()) for c in g if caps.get(c)]
        findings.append({
            'id': rule['id'], 'title': rule['title'], 'description': rule['description'],
            'tier': rule['tier'], 'pha': rule['pha'],
            'attack': attack(*rule['attack']), 'sources': cite(*rule['sources']),
            'legitimate_lookalikes': rule['lookalikes'],
            'evidence': {c: caps[c][:5] for c in used},
        })
    return findings
