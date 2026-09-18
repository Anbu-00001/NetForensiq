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
