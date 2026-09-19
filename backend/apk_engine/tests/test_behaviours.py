# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Behaviour rules, against a stand-in code map.

The rules are tested on facts rather than on real DEX files, so each test can
state exactly which capability is present and in whose code. The negative cases
matter most: they are the legitimate apps that hold one half of a rule — an app
store that installs packages, a firewall that routes everything into a VPN.
"""

import os
import unittest

from apk_engine.behaviours import detect_behaviours, detect_capabilities


class _Name:
    def __init__(self, value):
        self.name = value


class FakeSite:
    def __init__(self, caller='com.example.app.Main.run()', kind='app',
                 constants=None, references=()):
        self.caller = caller
        # Detectors that de-duplicate per calling method read these.
        self.caller_class = 'Lcom/example/app/Main;'
        self.caller_method = _Name('run')
        self.attribution = {'kind': kind, 'name': 'lib' if kind == 'library' else 'com.example.app'}
        self._constants = constants or []
        self._references = set(references)

    @property
    def counts_as_app_code(self):
        return self.attribution['kind'] in ('app', 'unattributed')

    def constant_arguments(self, _method):
        return self._constants

    def constant_values(self):
        values = set()
        for group in self._constants:
            for value in group:
                if isinstance(value, int):
                    values.add(value)
        return values

    def references(self, *values):
        return bool(self._references & set(values))

    def evidence(self, with_path=True):
        return {'caller': self.caller, 'attribution': self.attribution}


class FakeCodeMap:
    """Answers the queries the detectors make, from a table the test writes."""

    def __init__(self, calls=None, strings=None, libraries=(), dex_bytes=None):
        self.dex_bytes = dex_bytes
        self.call_table = calls or {}
        self.string_table = strings or {}
        # (dotted prefix, library name) pairs, as CodeMap holds them.
        self.libraries = tuple(libraries)

    def calls(self, owner, method, include_subclasses=False):
        return self.call_table.get((owner, method), [])

    def string_sites(self, regex):
        return self.string_table.get(regex, [])

    def attribute_component(self, component_name):
        for prefix, library in self.libraries:
            if component_name.startswith(prefix):
                return {'kind': 'library', 'name': library}
        return {'kind': 'app', 'name': 'com.example.app'}


IDENTITY = {
    'package': 'com.example.app', 'components': [], 'launcher_activities': [],
    'application_class': '',
}

INSTALL = ('Landroid/content/pm/PackageInstaller$Session;', 'commit')
VPN_ROUTE = ('Landroid/net/VpnService$Builder;', 'addRoute')
VPN_ESTABLISH = ('Landroid/net/VpnService$Builder;', 'establish')
TELEGRAM = r'api\.telegram\.org/bot'
NETWORK = ('Ljava/net/URL;', '<init>')


def run(identity=None, **codemap):
    ctx, capabilities = detect_capabilities(identity or IDENTITY, FakeCodeMap(**codemap))
    return {c['id']: c for c in capabilities}, {b['id']: b for b in detect_behaviours(ctx)}


class CapabilityTests(unittest.TestCase):
    def test_library_only_evidence_does_not_make_a_capability_present(self):
        capabilities, _ = run(calls={INSTALL: [FakeSite(kind='library')]})
        self.assertFalse(capabilities['cap.install_packages']['present'])
        self.assertEqual(capabilities['cap.install_packages']['library_only_occurrences'], 1)

    def test_obfuscated_code_counts_as_the_package_s_own(self):
        capabilities, _ = run(calls={INSTALL: [FakeSite(kind='unattributed')]})
        self.assertTrue(capabilities['cap.install_packages']['present'])

    def test_vpn_route_needs_a_catch_all_prefix(self):
        capabilities, _ = run(calls={VPN_ROUTE: [FakeSite(constants=[['10.0.0.2', 32]])]})
        self.assertFalse(capabilities['cap.vpn_catch_all_route']['present'])
        capabilities, _ = run(calls={VPN_ROUTE: [FakeSite(constants=[['0.0.0.0', 0]])]})
        self.assertTrue(capabilities['cap.vpn_catch_all_route']['present'])

    def test_launcher_icon_rule_needs_the_launcher_class_and_the_disabled_state(self):
        identity = dict(IDENTITY, launcher_activities=['com.example.app.MainActivity'])
        toggle = ('Landroid/content/pm/PackageManager;', 'setComponentEnabledSetting')
        # Disables a component, but not the launcher one.
        capabilities, _ = run(identity, calls={toggle: [
            FakeSite(constants=[[None, 2, 1]], references=['com.example.app.Other'])]})
        self.assertFalse(capabilities['cap.hides_launcher_icon']['present'])
        # Enables the launcher component rather than disabling it.
        capabilities, _ = run(identity, calls={toggle: [
            FakeSite(constants=[[None, 1, 1]], references=['com.example.app.MainActivity'])]})
        self.assertFalse(capabilities['cap.hides_launcher_icon']['present'])
        capabilities, _ = run(identity, calls={toggle: [
            FakeSite(constants=[[None, 2, 1]], references=['com.example.app.MainActivity'])]})
        self.assertTrue(capabilities['cap.hides_launcher_icon']['present'])


class BehaviourTests(unittest.TestCase):
    def test_installing_under_a_catch_all_vpn_fires(self):
        _caps, behaviours = run(calls={INSTALL: [FakeSite()],
                                       VPN_ROUTE: [FakeSite(constants=[['0.0.0.0', 0]])]})
        finding = behaviours['beh.install_under_network_blackout']
        self.assertEqual(finding['tier'], 3)
        self.assertEqual(finding['pha'], 'hostile-downloader')
        self.assertIn('T1407', [t['id'] for t in finding['attack']])
        self.assertTrue(finding['sources'])
        self.assertIn('cap.install_packages', finding['evidence'])

    def test_an_app_store_that_only_installs_does_not_fire(self):
        _caps, behaviours = run(calls={INSTALL: [FakeSite()]})
        self.assertNotIn('beh.install_under_network_blackout', behaviours)

    def test_a_firewall_that_only_routes_does_not_fire(self):
        _caps, behaviours = run(calls={VPN_ROUTE: [FakeSite(constants=[['0.0.0.0', 0]])],
                                       VPN_ESTABLISH: [FakeSite()]})
        self.assertNotIn('beh.install_under_network_blackout', behaviours)

    def test_library_code_on_one_side_does_not_complete_the_rule(self):
        _caps, behaviours = run(calls={INSTALL: [FakeSite(kind='library')],
                                       VPN_ROUTE: [FakeSite(constants=[['0.0.0.0', 0]])]})
        self.assertNotIn('beh.install_under_network_blackout', behaviours)

    def test_sms_to_telegram_bot_needs_both_halves(self):
        identity = dict(IDENTITY, components=[{
            'kind': 'receiver', 'name': 'com.example.app.SmsRx', 'permission': '',
            'intent_filters': [{'actions': ['android.provider.Telephony.SMS_RECEIVED'],
                                'categories': []}]}])
        _caps, behaviours = run(identity)
        self.assertNotIn('beh.sms_to_telegram_bot', behaviours)
        _caps, behaviours = run(identity, strings={TELEGRAM: [FakeSite()]})
        finding = behaviours['beh.sms_to_telegram_bot']
        self.assertEqual(finding['pha'], 'spyware')
        self.assertIn('T1636.004', [t['id'] for t in finding['attack']])

    def test_a_receiver_the_manifest_merger_copied_in_is_not_the_app_s(self):
        """
        The manifest merger copies an SDK's components into the app's manifest,
        so an SMS receiver declared by a bundled library is indistinguishable
        from one the app wrote until it is attributed. Before that attribution
        existed, this rule could be completed by a library's receiver.
        """
        identity = dict(IDENTITY, components=[{
            'kind': 'receiver', 'name': 'com.someSdk.messaging.SmsRx', 'permission': '',
            'intent_filters': [{'actions': ['android.provider.Telephony.SMS_RECEIVED'],
                                'categories': []}]}])
        capabilities, behaviours = run(
            identity, strings={TELEGRAM: [FakeSite()]},
            libraries=(('com.someSdk.', 'Some SDK'),))
        self.assertFalse(capabilities['cap.sms_receiver']['present'])
        self.assertEqual(capabilities['cap.sms_receiver']['library_only_occurrences'], 1)
        self.assertNotIn('beh.sms_to_telegram_bot', behaviours)

    def test_a_dropper_needs_both_the_installer_and_a_payload_to_install(self):
        identity = dict(IDENTITY, bundled_packages=['assets/payload.dat (archive, 900,000 bytes)'])
        _caps, behaviours = run(identity, calls={INSTALL: [FakeSite()]})
        self.assertIn('beh.dropper_with_bundled_payload', behaviours)
        # An app store installs packages but carries no payload of its own.
        _caps, behaviours = run(IDENTITY, calls={INSTALL: [FakeSite()]})
        self.assertNotIn('beh.dropper_with_bundled_payload', behaviours)

    def test_runtime_code_loading_alone_is_not_the_behaviour(self):
        loader = ('Ldalvik/system/DexClassLoader;', '<init>')
        _caps, behaviours = run(calls={loader: [FakeSite()]})
        self.assertNotIn('beh.runtime_code_from_network', behaviours)
        _caps, behaviours = run(calls={loader: [FakeSite()], NETWORK: [FakeSite()]})
        self.assertIn('beh.runtime_code_from_network', behaviours)

    def test_typing_into_other_apps_needs_set_text_not_merely_a_gesture(self):
        perform = ('Landroid/view/accessibility/AccessibilityNodeInfo;', 'performAction')
        overlay = ('Landroid/view/WindowManager;', 'addView')
        # A gesture with some other action constant is not text entry.
        caps, behaviours = run(calls={perform: [FakeSite(constants=[[1]])],
                                      overlay: [FakeSite(constants=[[2038]])]})
        self.assertFalse(caps['cap.accessibility_text_entry']['present'])
        self.assertNotIn('beh.accessibility_types_into_other_apps', behaviours)
        # ACTION_SET_TEXT, drawn over another app, is the device-takeover pattern.
        caps, behaviours = run(calls={perform: [FakeSite(constants=[[2097152]])],
                                      overlay: [FakeSite(constants=[[2038]])]})
        self.assertTrue(caps['cap.accessibility_text_entry']['present'])
        finding = behaviours['beh.accessibility_types_into_other_apps']
        self.assertEqual(finding['tier'], 3)
        self.assertTrue(finding['sources'])

    def test_screen_capture_only_counts_when_it_can_leave_the_device(self):
        capture = ('Landroid/media/projection/MediaProjection;', 'createVirtualDisplay')
        _caps, behaviours = run(calls={capture: [FakeSite()]})
        self.assertNotIn('beh.screen_capture_to_network', behaviours)
        _caps, behaviours = run(calls={capture: [FakeSite()], NETWORK: [FakeSite()]})
        self.assertIn('beh.screen_capture_to_network', behaviours)

    def test_the_tv_box_dropper_rule_needs_all_three_halves(self):
        shell = ('Ljava/lang/Runtime;', 'exec')
        boot = dict(IDENTITY, components=[{
            'kind': 'receiver', 'name': 'com.example.app.Boot', 'permission': '',
            'intent_filters': [{'actions': ['android.intent.action.BOOT_COMPLETED'],
                                'categories': []}]}])
        _caps, behaviours = run(boot, calls={INSTALL: [FakeSite()]})
        self.assertNotIn('beh.adb_payload_dropper', behaviours)
        _caps, behaviours = run(boot, calls={INSTALL: [FakeSite()], shell: [FakeSite()]})
        self.assertIn('beh.adb_payload_dropper', behaviours)

    def test_target_sdk_capability_reflects_the_manifest(self):
        caps, _ = run(dict(IDENTITY, target_sdk=22))
        self.assertTrue(caps['cap.targets_pre_marshmallow']['present'])
        caps, _ = run(dict(IDENTITY, target_sdk=34))
        self.assertFalse(caps['cap.targets_pre_marshmallow']['present'])
        caps, _ = run(IDENTITY)
        self.assertFalse(caps['cap.targets_pre_marshmallow']['present'])

    def test_every_rule_declares_sources_lookalikes_and_a_tier(self):
        from apk_engine.behaviours import BEHAVIOURS
        for rule in BEHAVIOURS:
            self.assertIn(rule['tier'], (2, 3), rule['id'])
            self.assertTrue(rule['sources'], rule['id'])
            self.assertTrue(rule['lookalikes'], rule['id'])
            self.assertTrue(rule['attack'], rule['id'])


ISODEP = ('Landroid/nfc/tech/IsoDep;', 'transceive')
BLOB = {'name': 'assets/dbliqgnjl.dat', 'size': 5_531_000, 'entropy': 7.9991}


def _perms(count):
    return [{'name': f'android.permission.P{i}'} for i in range(count)]


class NfcRelayTests(unittest.TestCase):
    """CERT Polska (NGate) and Cleafy (SuperCard X): read the card, relay it, ask for little."""

    def test_all_three_parts_are_needed(self):
        few = dict(IDENTITY, permissions=_perms(4))
        _c, beh = run(few, calls={ISODEP: [FakeSite()], NETWORK: [FakeSite()]})
        self.assertIn('beh.nfc_card_relay', beh)
        _c, beh = run(few, calls={ISODEP: [FakeSite()]})                  # no network
        self.assertNotIn('beh.nfc_card_relay', beh)
        _c, beh = run(few, calls={NETWORK: [FakeSite()]})                 # no card read
        self.assertNotIn('beh.nfc_card_relay', beh)

    def test_a_payment_terminal_with_a_full_permission_set_does_not_match(self):
        # The one legitimate IsoDep + network app in the corpus declared 17.
        terminal = dict(IDENTITY, permissions=_perms(17))
        _c, beh = run(terminal, calls={ISODEP: [FakeSite()], NETWORK: [FakeSite()]})
        self.assertNotIn('beh.nfc_card_relay', beh)

    def test_threshold_is_inclusive_and_no_permissions_at_all_does_not_count(self):
        from apk_engine.behaviours import MINIMAL_PERMISSIONS
        caps, _ = run(dict(IDENTITY, permissions=_perms(MINIMAL_PERMISSIONS)))
        self.assertTrue(caps['cap.minimal_permission_set']['present'])
        caps, _ = run(dict(IDENTITY, permissions=_perms(MINIMAL_PERMISSIONS + 1)))
        self.assertFalse(caps['cap.minimal_permission_set']['present'])
        caps, _ = run(dict(IDENTITY, permissions=[]))
        self.assertFalse(caps['cap.minimal_permission_set']['present'])

    def test_a_library_reading_cards_is_not_the_app_reading_cards(self):
        few = dict(IDENTITY, permissions=_perms(4))
        _c, beh = run(few, calls={ISODEP: [FakeSite(kind='library')], NETWORK: [FakeSite()]})
        self.assertNotIn('beh.nfc_card_relay', beh)


class PackedPayloadTests(unittest.TestCase):
    """Stub DEX beside an opaque payload — evasion evidence, tier 2, no PHA claim."""

    def test_stub_dex_beside_a_random_blob_matches(self):
        caps, beh = run(dict(IDENTITY, opaque_payloads=[BLOB]), dex_bytes=72_000)
        self.assertTrue(caps['cap.encrypted_code_payload']['present'])
        self.assertIn('beh.packed_code_payload', beh)
        self.assertEqual(beh['beh.packed_code_payload']['tier'], 2)
        self.assertIsNone(beh['beh.packed_code_payload']['pha'])

    def test_a_full_sized_dex_is_an_app_not_a_loader(self):
        caps, _ = run(dict(IDENTITY, opaque_payloads=[BLOB]), dex_bytes=3_400_000)
        self.assertFalse(caps['cap.encrypted_code_payload']['present'])

    def test_a_stub_dex_with_no_payload_is_not_packing(self):
        caps, _ = run(dict(IDENTITY, opaque_payloads=[]), dex_bytes=15_000)
        self.assertFalse(caps['cap.encrypted_code_payload']['present'])

    def test_unknown_dex_size_never_matches(self):
        caps, _ = run(dict(IDENTITY, opaque_payloads=[BLOB]))            # dex_bytes None
        self.assertFalse(caps['cap.encrypted_code_payload']['present'])


class OpaquePayloadScanTests(unittest.TestCase):
    """frameworks.opaque_payloads on real ZIP bytes."""

    def _apk(self, entries):
        import tempfile, zipfile
        handle = tempfile.NamedTemporaryFile(suffix='.apk', delete=False)
        with zipfile.ZipFile(handle, 'w', zipfile.ZIP_STORED) as z:
            for name, data in entries:
                z.writestr(name, data)
        self.addCleanup(__import__('os').unlink, handle.name)
        return handle.name

    def test_random_bytes_are_found_whatever_the_name(self):
        from apk_engine import frameworks
        path = self._apk([('assets/core_profile.pak', os.urandom(1_200_000)),
                          ('assets/background.dat', b'\x00' * 1_200_000)])
        found = [b['name'] for b in frameworks.opaque_payloads(path)]
        self.assertEqual(found, ['assets/core_profile.pak'])

    def test_native_libraries_and_small_entries_are_not_read(self):
        from apk_engine import frameworks
        path = self._apk([('lib/arm64-v8a/libx.so', os.urandom(1_200_000)),
                          ('assets/small.bin', os.urandom(400_000))])
        self.assertEqual(frameworks.opaque_payloads(path), [])

    def test_a_corrupt_archive_yields_nothing_rather_than_raising(self):
        from apk_engine import frameworks
        path = self._apk([])
        with open(path, 'wb') as fh:
            fh.write(b'not a zip')
        self.assertEqual(frameworks.opaque_payloads(path), [])



class FrameworkAttributionTests(unittest.TestCase):
    """
    Framework bootstrap code is the framework's, not the developer's.

    Regression for the first false positive the held-out benign set produced:
    a Qt app whose only "runtime code loading" and "network use" were Qt's own
    QtLoader and clipboard code, attributed to nobody and so counted as the app's.
    """

    def _codemap_with_known_namespaces(self):
        from apk_engine.codemap import CodeMap, WELL_KNOWN_NAMESPACES
        cm = CodeMap.__new__(CodeMap)
        cm._libraries = sorted(WELL_KNOWN_NAMESPACES.items(), key=lambda p: -len(p[0]))
        cm._app_prefixes = ('priv.wh201906.',)
        cm.identity = {'package': 'priv.wh201906.serialtest'}
        return cm

    def test_qt5_and_qt6_bindings_are_attributed_to_qt(self):
        cm = self._codemap_with_known_namespaces()
        for cls in ('Lorg/qtproject/qt5/android/bindings/QtLoader;',
                    'Lorg/qtproject/qt5/android/QtNative;',
                    'Lorg/qtproject/qt/android/QtNative;'):
            self.assertEqual(cm.attribute(cls)['kind'], 'library', cls)

    def test_the_developer_s_own_code_is_still_the_app_s(self):
        cm = self._codemap_with_known_namespaces()
        self.assertEqual(cm.attribute('Lpriv/wh201906/serialtest/Main;')['kind'], 'app')
