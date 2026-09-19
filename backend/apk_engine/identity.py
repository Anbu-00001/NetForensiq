# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
What the package says about itself: manifest, components, permissions, signers.

Everything here is description, not judgement. Two things the old module got
wrong are fixed at this layer:

* **Signatures.** It looked for signature files under META-INF/ and reported
  "No signing block found" for every APK signed only with scheme v2/v3, whose
  signatures live in the APK Signing Block (Android ≥ 7.0 / ≥ 9) — 10 of 31
  legitimate apps in the evaluation corpus. androguard reads all schemes.
* **Permissions.** It scored each permission with a hand-picked weight. Here a
  permission is listed with Android's own label, description and protection
  level, taken from the AOSP data androguard bundles. A permission is a
  capability the user or platform grants; Google Play itself allows READ_SMS
  for UPI apps. It is not evidence of intent, and nothing in this module
  claims it is.
"""

import hashlib

ANDROID_NS = '{http://schemas.android.com/apk/res/android}'
COMPONENT_TAGS = ('activity', 'activity-alias', 'service', 'receiver', 'provider')

# The subject Android's build tools write into the auto-generated debug
# certificate. Observed on every locally built debug APK examined; Google Play
# does not accept apps signed with it (android-app-signing).
DEBUG_SUBJECT = {'common_name': 'Android Debug', 'organization_name': 'Android',
                 'country_name': 'US'}

MAX_COMPONENTS = 400


def _attr(element, name):
    # A manifest with blanked attribute-name strings (axml.attribute_names —
    # the judge's dropper has it) still parses, because androguard recovers
    # the names from the resource map. It then emits them without the android
    # namespace. Reading only the namespaced key made that sample's VPN
    # service invisible, which is exactly the outcome the tampering is for.
    value = element.get(ANDROID_NS + name)
    return value if value is not None else element.get(name)


def _components(manifest):
    components = []
    if manifest is None:
        return components
    application = manifest.find('application')
    if application is None:
        return components
    for tag in COMPONENT_TAGS:
        for element in application.iter(tag):
            filters = []
            for intent_filter in element.findall('intent-filter'):
                filters.append({
                    'actions': [_attr(a, 'name') for a in intent_filter.findall('action')
                                if _attr(a, 'name')],
                    'categories': [_attr(c, 'name') for c in intent_filter.findall('category')
                                   if _attr(c, 'name')],
                })
            components.append({
                'kind': tag,
                'name': _attr(element, 'name') or '',
                'target': _attr(element, 'targetActivity') or '',
                'exported': _attr(element, 'exported'),
                'enabled': _attr(element, 'enabled'),
                'permission': _attr(element, 'permission') or '',
                'intent_filters': filters,
            })
            if len(components) >= MAX_COMPONENTS:
                return components
    return components


def _permission_metadata(target_sdk):
    """AOSP permission definitions for the nearest API level androguard bundles."""
    from androguard.core.api_specific_resources import load_permissions
    for level in [min(max(target_sdk or 0, 9), 36)] + list(range(36, 8, -1)):
        try:
            data = load_permissions(level)
            if data:
                return level, data
        except Exception:
            continue
    return None, {}


def _certificate(cert):
    der = cert.dump()
    subject = cert.subject.native
    anomalies = []
    country = subject.get('country_name')
    if country is not None and len(str(country)) != 2:
        anomalies.append({
            'id': 'cert.malformed_country',
            'detail': f'countryName is {country!r}; RFC 5280 defines it as exactly two characters.',
        })
    return {
        'subject': cert.subject.human_friendly,
        'issuer': cert.issuer.human_friendly,
        'self_signed': cert.subject == cert.issuer,
        'serial': str(cert.serial_number),
        'not_before': cert['tbs_certificate']['validity']['not_before'].native.isoformat(),
        'not_after': cert['tbs_certificate']['validity']['not_after'].native.isoformat(),
        'sha256': hashlib.sha256(der).hexdigest(),
        'sha1': hashlib.sha1(der).hexdigest().upper(),
        'debug_certificate': all(subject.get(k) == v for k, v in DEBUG_SUBJECT.items()),
        'subject_anomalies': anomalies,
    }


def read_identity(apk):
    """Describe an androguard ``APK``. Each field fails independently."""
    identity = {
        'package': '', 'label': '', 'version_name': '', 'version_code': '',
        'min_sdk': None, 'target_sdk': None,
        'debuggable': False, 'uses_cleartext_traffic': None,
        'application_class': '',
        'launcher_activities': [], 'components': [],
        'permissions': [], 'permission_api_level': None,
        'signing': {'schemes': {}, 'certificates': []},
        'errors': [],
    }

    def attempt(label, fn):
        try:
            return fn()
        except Exception as exc:
            identity['errors'].append(f'{label}: {exc}')
            return None

    identity['package'] = attempt('package', apk.get_package) or ''
    identity['label'] = attempt('label', apk.get_app_name) or ''
    identity['version_name'] = attempt('version name', apk.get_androidversion_name) or ''
    identity['version_code'] = attempt('version code', apk.get_androidversion_code) or ''

    def as_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    identity['min_sdk'] = as_int(attempt('minSdk', apk.get_min_sdk_version))
    identity['target_sdk'] = as_int(attempt('targetSdk', apk.get_target_sdk_version))
    identity['debuggable'] = attempt(
        'debuggable', lambda: apk.get_attribute_value('application', 'debuggable')) == 'true'
    cleartext = attempt('cleartext',
                        lambda: apk.get_attribute_value('application', 'usesCleartextTraffic'))
    identity['uses_cleartext_traffic'] = None if cleartext is None else cleartext == 'true'
    identity['application_class'] = attempt(
        'application class', lambda: apk.get_attribute_value('application', 'name')) or ''
    identity['launcher_activities'] = sorted(attempt('launcher', apk.get_main_activities) or [])

    manifest = attempt('manifest', apk.get_android_manifest_xml)
    identity['components'] = attempt('components', lambda: _components(manifest)) or []

    level, metadata = attempt('permission metadata',
                              lambda: _permission_metadata(identity['target_sdk'])) or (None, {})
    identity['permission_api_level'] = level
    for name in sorted(set(attempt('permissions', apk.get_permissions) or [])):
        meta = metadata.get(name)
        identity['permissions'].append({
            'name': name,
            'defined_by_aosp': meta is not None,
            'protection_level': (meta or {}).get('protectionLevel', ''),
            'label': (meta or {}).get('label', ''),
            'description': ' '.join(((meta or {}).get('description') or '').split()),
        })

    identity['signing']['schemes'] = {
        'v1': bool(attempt('v1 signature', apk.is_signed_v1)),
        'v2': bool(attempt('v2 signature', apk.is_signed_v2)),
        'v3': bool(attempt('v3 signature', apk.is_signed_v3)),
    }
    seen = set()
    for cert in attempt('certificates', apk.get_certificates) or []:
        described = attempt('certificate', lambda c=cert: _certificate(c))
        if described and described['sha256'] not in seen:
            seen.add(described['sha256'])
            identity['signing']['certificates'].append(described)
    return identity


def components_with_action(identity, action, kinds=('receiver',)):
    return [c['name'] for c in identity['components']
            if c['kind'] in kinds
            and any(action in f['actions'] for f in c['intent_filters'])]


def components_with_permission(identity, permission, kinds=('service', 'receiver')):
    return [c['name'] for c in identity['components']
            if c['kind'] in kinds and c['permission'] == permission]
