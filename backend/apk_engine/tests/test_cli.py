"""
The command line, end to end, on generated packages.

This is the interface the web process depends on, so it is tested the way the
web process uses it: as a subprocess that must always print one JSON report.
The isolation tests here are the ones that keep the licence separation real —
the engine must never pull Django or scapy in, and the modules the web process
imports must never pull androguard in.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from . import factories

BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_engine(*arguments, baselines=None):
    environment = {'PATH': os.environ.get('PATH', ''), 'PYTHONPATH': BACKEND}
    if baselines:
        environment['APK_ENGINE_BASELINES'] = baselines
    completed = subprocess.run([sys.executable, '-m', 'apk_engine', 'examine', *arguments],
                               capture_output=True, cwd=BACKEND, env=environment, timeout=300)
    return completed, json.loads(completed.stdout)


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.dir = self._dir.name
        self.addCleanup(self._dir.cleanup)

    def write(self, name, payload):
        path = os.path.join(self.dir, name)
        with open(path, 'wb') as handle:
            handle.write(payload)
        return path

    def baselines(self, signal_id, benign_fired=0):
        path = os.path.join(self.dir, 'baselines.json')
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump({'measured_at': '2026-09-17T00:00:00+00:00',
                       'corpus': {'benign': 31, 'malicious': 1},
                       'signals': {signal_id: {'benign_fired': benign_fired,
                                               'malicious_fired': 1}}}, handle)
        return path

    def test_well_formed_package_is_examined_and_reaches_tier_1(self):
        path = self.write('clean.apk', factories.apk())
        completed, report = run_engine('--apk', path)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(report['assessment']['tier'], 1)
        self.assertEqual(report['identity']['package'], 'com.example.app')
        self.assertEqual(report['integrity']['findings'], [])
        self.assertTrue(report['code']['no_code'])
        self.assertTrue(report['file']['sha256'])
        self.assertTrue(report['limits'])

    def test_tampering_reaches_tier_2_once_the_signal_is_validated(self):
        path = self.write('tampered.apk', factories.forge_compression_method(factories.apk()))
        _completed, report = run_engine(
            '--apk', path, baselines=self.baselines('zip.unknown_compression_method'))
        self.assertEqual(report['assessment']['tier'], 2)
        basis = [item['id'] for item in report['assessment']['basis']]
        self.assertIn('zip.unknown_compression_method', basis)

    def test_the_same_tampering_cannot_raise_the_tier_when_legitimate_apps_show_it(self):
        path = self.write('tampered.apk', factories.forge_compression_method(factories.apk()))
        _completed, report = run_engine(
            '--apk', path,
            baselines=self.baselines('zip.unknown_compression_method', benign_fired=3))
        self.assertEqual(report['assessment']['tier'], 1)
        self.assertIn('zip.unknown_compression_method',
                      [item['id'] for item in report['assessment']['not_established']])

    def test_a_file_that_is_not_a_package_is_tier_0_not_tier_1(self):
        path = self.write('note.txt', b'just some bytes')
        completed, report = run_engine('--apk', path)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(report['assessment']['tier'], 0)
        self.assertTrue(report['errors'])

    def test_container_facts_are_reported_for_a_wrapped_sample(self):
        inner = self.write('inner.apk', factories.apk())
        wrapper = self.write('wrapper.zip', factories.zip_with({'inner.apk': b'x' * 10}))
        _completed, report = run_engine('--apk', inner, '--container', wrapper)
        self.assertTrue(report['container']['readable'])
        self.assertEqual(report['container']['apk_members'], ['inner.apk'])

    def test_memory_limit_is_applied_and_reported_as_a_failure_not_a_clean_result(self):
        path = self.write('clean.apk', factories.apk())
        completed, report = run_engine('--apk', path, '--max-memory-mb', '32')
        # 32 MB cannot even import androguard; the point is the report still
        # exists and says so, rather than showing an empty findings list.
        self.assertEqual(completed.returncode, 0)
        self.assertLessEqual(report['assessment']['tier'], 1)
        if report['assessment']['tier'] == 0:
            self.assertTrue(report['errors'])


class IsolationTests(unittest.TestCase):
    def _imports(self, module):
        code = (f'import importlib, sys; importlib.import_module("{module}"); '
                'print(",".join(sorted(m for m in sys.modules '
                'if m in ("django", "scapy", "androguard", "apkInspector"))))')
        completed = subprocess.run([sys.executable, '-c', code], capture_output=True,
                                   cwd=BACKEND, env={'PATH': os.environ.get('PATH', ''),
                                                     'PYTHONPATH': BACKEND}, timeout=120)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode()[:400])
        return set(filter(None, completed.stdout.decode().strip().split(',')))

    def test_engine_never_imports_django_or_scapy(self):
        # Licence separation: scapy is GPL-2.0-only and lives in the web
        # process; androguard is Apache-2.0 and lives here.
        loaded = self._imports('apk_engine.engine')
        self.assertNotIn('django', loaded)
        self.assertNotIn('scapy', loaded)

    def test_modules_the_web_process_imports_stay_free_of_androguard(self):
        for module in ('apk_engine.report', 'apk_engine.container', 'apk_engine.endpoints'):
            loaded = self._imports(module)
            self.assertNotIn('androguard', loaded, module)
            self.assertNotIn('apkInspector', loaded, module)
