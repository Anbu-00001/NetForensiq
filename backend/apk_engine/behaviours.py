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
