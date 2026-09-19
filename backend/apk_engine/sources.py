"""
Every published source a finding may cite, in one place.

A finding that says "this technique is used by malware" is only as good as the
document behind it, so findings cite by key and the report carries the full
reference. ``verified`` records whether the primary document itself was read
(True) or only a secondary account of it (False) — the same ✅/⚠️ rule as
research/150_APK_MALWARE_CLASSIFICATION.md. The interface shows the difference;
a secondary source is never displayed as if it were primary.
"""

SOURCES = {
    # Added 19 Sep 2026. Every entry below was re-opened and its wording checked
    # by a separate audit pass before being cited (apk_corpus/analysis/research/
    # AUDIT_2026-09-19.md); 'verified' records that check, not a guess.
    'threatfabric-herodotus-2025': {
        'title': 'Herodotus: new Android malware mimics human behaviour to evade detection',
        'publisher': 'ThreatFabric', 'date': '2025-10-28',
        'url': 'https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection',
        'verified': True,
    },
    'zimperium-pixrevolution-2026': {
        'title': 'PixRevolution: the agent-operated Android trojan hijacking Brazil\'s Pix payments',
        'publisher': 'Zimperium zLabs', 'date': '2026-03-11',
        'url': 'https://zimperium.com/blog/pixrevolution-the-agent-operated-android-trojan-hijacking-brazils-pix-payments-in-real-time',
        'verified': True,
    },
    'zscaler-copybara-2024': {
        'title': 'Technical analysis of Copybara',
        'publisher': 'Zscaler ThreatLabz', 'date': '2024-08-21',
        'url': 'https://www.zscaler.com/blogs/security-research/technical-analysis-copybara',
        'verified': True,
    },
    'cyfirma-spynote-2024': {
        'title': 'SpyNote: unmasking a sophisticated Android malware',
        'publisher': 'CYFIRMA', 'date': '2024-11-06',
        'url': 'https://www.cyfirma.com/research/spynote-unmasking-a-sophisticated-android-malware/',
        'verified': True,
    },
    'threatfabric-securidropper-2023': {
        'title': 'Droppers bypassing Android 13 restrictions (SecuriDropper)',
        'publisher': 'ThreatFabric', 'date': '2023-11-01',
        'url': 'https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions',
        'verified': True,
    },
    'android-dcl-policy': {
        'title': 'Dynamic code loading, and the Play policy against executable code from '
                 'outside Google Play',
        'publisher': 'Android Developers', 'date': '2024',
        'url': 'https://developer.android.com/privacy-and-security/risks/dynamic-code-loading',
        'verified': True,
    },
    'android-target-api-2019': {
        'title': 'Expanding target API level requirements in 2019 — "Over 95% of spyware we '
                 'detect outside of the Play Store intentionally targets API level 22 or lower"',
        'publisher': 'Android Developers Blog', 'date': '2019-02-14',
        'url': 'https://android-developers.googleblog.com/2019/02/expanding-target-api-level-requirements.html',
        'verified': True,
    },
    'android-14-behaviour-all': {
        'title': 'Behaviour changes: all apps (Android 14) — minimum installable targetSdkVersion',
        'publisher': 'Android Developers', 'date': '2023',
        'url': 'https://developer.android.com/about/versions/14/behavior-changes-all',
        'verified': True,
    },
    'comcast-jackskid-2026': {
        'title': 'Reverse-engineering JackSkid: from bare-bones Mirai fork to persistent TV-box botnet',
        'publisher': 'Comcast (corporate.comcast.com/stories)', 'date': '2026-03-24',
        'url': 'https://corporate.comcast.com/stories/reverse-engineering-jackskid-from-bare-bones-mirai-fork-to-persistent-tv-box-botnet',
        'verified': True,
    },
    'rescana-kimwolf-2026': {
        'title': 'Kimwolf botnet: Android TV box and IoT malware exploiting ADB on TCP/5555',
        'publisher': 'Rescana', 'date': '2026-01-06',
        'url': 'https://rescana.com/post/kimwolf-botnet-massive-android-tv-box-and-iot-malware-threat-exploiting-global-networks',
        'verified': True,
    },
    'zimperium-2023-compression': {
        'title': 'Unsupported compression methods enable Android malware to bypass detection',
        'publisher': 'Zimperium zLabs', 'date': '2023-08-16',
        'url': 'https://zimperium.com/blog/over-3000-android-malware-samples-using-multiple-techniques-to-bypass-detection',
        'verified': True,
    },
    'konfety-2025': {
        'title': 'Android malware Konfety evolves with ZIP manipulation and dynamic loading',
        'publisher': 'SecurityAffairs, reporting Zimperium zLabs', 'date': '2025-07-15',
        'url': 'https://securityaffairs.com/179969/malware/android-malware-konfety-evolves-with-zip-manipulation-and-dynamic-loading.html',
        'verified': False,
    },
    'apkinspector': {
        'title': 'apkInspector — static analysis evasion detection (DEF CON 32)',
        'publisher': 'erev0s', 'date': '2024',
        'url': 'https://github.com/erev0s/apkInspector',
        'verified': True,
    },
    'cyfirma-2025-rto': {
        'title': 'RTO Challan Fraud: a technical report on APK-based financial and identity theft',
        'publisher': 'CYFIRMA', 'date': '2025-12-11',
        'url': 'https://www.cyfirma.com/research/rto-challan-fraud-a-technical-report-on-apk-based-financial-and-identity-theft/',
        'verified': True,
    },
    'toxicpanda-2026': {
        'title': 'ToxicPanda Android malware uses VPN permissions to block Google Play',
        'publisher': 'BleepingComputer, reporting Zimperium', 'date': '2026-08-23',
        'url': 'https://www.bleepingcomputer.com/news/security/toxicpanda-android-malware-uses-vpn-permissions-to-block-google-play/',
        'verified': False,
    },
    'proofpoint-2024-trycloudflare': {
        'title': 'Threat actor abuses Cloudflare tunnels to deliver RATs',
        'publisher': 'Proofpoint', 'date': '2024-08',
        'url': 'https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats',
        'verified': False,
    },
    'securelist-2025-tria': {
        'title': 'Tria stealer targets Android users for SMS exfiltration and financial gain',
        'publisher': 'Kaspersky Securelist', 'date': '2025-01-30',
        'url': 'https://securelist.com/tria-stealer-collects-sms-data-from-android-devices/115295/',
        'verified': True,
    },
    'unit42-2018-telerat': {
        'title': "TeleRAT: another Android trojan leveraging Telegram's Bot API",
        'publisher': 'Palo Alto Networks Unit 42', 'date': '2018-03-20',
        'url': 'https://unit42.paloaltonetworks.com/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/',
        'verified': True,
    },
    'telegram-bot-api': {
        'title': 'Telegram Bot API — making requests',
        'publisher': 'Telegram', 'date': 'living document',
        'url': 'https://core.telegram.org/bots/api',
        'verified': True,
    },
    'cloak-and-dagger-2017': {
        'title': 'Cloak and Dagger: from two permissions to complete control of the UI feedback loop',
        'publisher': 'Fratantonio et al., IEEE S&P 2017', 'date': '2017',
        'url': 'https://ieeexplore.ieee.org/document/7958624/',
        'verified': False,
    },
    'google-pha': {
        'title': 'Potentially Harmful Application (PHA) / malware categories',
        'publisher': 'Google', 'date': 'living document',
        'url': 'https://developers.google.com/android/play-protect/phacategories',
        'verified': True,
    },
    'google-play-sms-policy': {
        'title': 'Use of SMS or Call Log permission groups',
        'publisher': 'Google Play Console Help', 'date': 'living document',
        'url': 'https://support.google.com/googleplay/android-developer/answer/10208820',
        'verified': True,
    },
    'aosp-apk-signing': {
        'title': 'APK signing',
        'publisher': 'Android Open Source Project', 'date': 'living document',
        'url': 'https://source.android.com/docs/security/features/apksigning',
        'verified': True,
    },
    'android-app-signing': {
        'title': 'Sign your app — debug certificate',
        'publisher': 'Android Developers', 'date': 'living document',
        'url': 'https://developer.android.com/studio/publish/app-signing',
        'verified': True,
    },
    'rfc5280': {
        'title': 'RFC 5280 — X520countryName ::= PrintableString (SIZE (2))',
        'publisher': 'IETF', 'date': '2008-05',
        'url': 'https://www.rfc-editor.org/rfc/rfc5280',
        'verified': True,
    },
    'mitre-attack-mobile': {
        'title': 'MITRE ATT&CK for Mobile',
        'publisher': 'MITRE', 'date': 'v19',
        'url': 'https://attack.mitre.org/matrices/mobile/android/',
        'verified': True,
    },
    'dos-and-donts-2022': {
        'title': "Dos and Don'ts of Machine Learning in Computer Security (P8: base-rate fallacy)",
        'publisher': 'Arp et al., USENIX Security 2022', 'date': '2022',
        'url': 'https://www.usenix.org/system/files/sec22summer_arp.pdf',
        'verified': True,
    },
}


# MITRE ATT&CK for Mobile technique names, each fetched from attack.mitre.org
# (v19) when this table was written. Only IDs a rule actually maps to are here.
ATTACK = {
    'T1406': 'Obfuscated Files or Information',
    'T1407': 'Download New Code at Runtime',
    'T1481.003': 'Web Service: One-Way Communication',
    'T1516': 'Input Injection',
    'T1417.002': 'Input Capture: GUI Input Capture',
    'T1628.001': 'Hide Artifacts: Suppress Application Icon',
    'T1629.003': 'Impair Defenses: Disable or Modify Tools',
    'T1636.004': 'Protected User Data: SMS Messages',
    'T1513': 'Screen Capture',   # Mobile matrix, Collection — verified 19 Sep 2026
}


# Google's PHA categories, with the definition quoted from the category page.
PHA = {
    'hostile-downloader': {
        'name': 'Hostile downloader',
        'definition': "Code that isn't in itself potentially harmful, but downloads other PHAs.",
    },
    'spyware': {
        'name': 'Spyware',
        'definition': ('Malicious application, code, or behavior that collects, exfiltrates, '
                       'or shares user or device data not related to policy compliant functionality.'),
    },
    'stalkerware': {
        'name': 'Stalkerware',
        'definition': ('Code that collects personal or sensitive user data from a device and '
                       'transmits the data to a third party for monitoring purposes.'),
    },
}


def cite(*keys):
    """Expand source keys into the reference objects a report carries."""
    return [dict(SOURCES[k], key=k) for k in keys]


def attack(*ids):
    return [{'id': i, 'name': ATTACK[i],
             'url': f'https://attack.mitre.org/techniques/{i.replace(".", "/")}/'}
            for i in ids]
