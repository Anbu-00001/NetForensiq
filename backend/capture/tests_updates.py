# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Signed update bundles (evidence/update_bundle.py, capture/updates.py).

Organised by the attack each group of tests answers, using The Update Framework's
list (https://theupdateframework.io/docs/security/): arbitrary content, rollback,
indefinite freeze, endless data, mix-and-match, wrong content installed — and the
two it does not prevent, which are stated rather than tested away: a fast-forward
by a holder of the key, and compromise of a single key.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase, override_settings

from apk_engine import reference
from evidence import signing, update_bundle
from evidence.update_bundle import BadSignature, MalformedBundle

from . import updates
from .models import IOCFeed, UpdateBundle

REPO = Path(__file__).resolve().parents[2]
BACKEND = REPO / 'backend'

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
SOON = (NOW + timedelta(days=90)).isoformat()
PAST = (NOW - timedelta(days=1)).isoformat()

PUBLISHER_A = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
PUBLISHER_B = Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32)

FEED = b'203.0.113.5\n198.51.100.7\n192.0.2.44\n'
STALKERWARE = json.dumps({'indicators': ['com.example.spy'], 'note': 'test data'}).encode()
TLDS = b'# test list\ncom\norg\nnet\n'


def fingerprint_of(key):
    return signing.fingerprint(signing.public_key_bytes(key))


def make(files=None, *, items, sequence=1, expires=SOON, key=PUBLISHER_A, publisher='Test lab',
         created=None):
    """Build a bundle from `items`, whose `path`s are keys of `files`."""
    files = files or {}
    spec = {'publisher': publisher, 'sequence': sequence, 'expires': expires, 'items': items}
    if created:
        spec['created'] = created
    else:
        spec['created'] = (NOW - timedelta(hours=1)).isoformat()
    return update_bundle.build_bundle(spec, lambda path: files[path], key)


def feed_item(path='feed.txt', name='Test feed', fmt='plain_ip', retrieved='2026-10-01'):
    return {'type': 'ioc_feed', 'path': path, 'name': name, 'format': fmt,
            'retrieved_on': retrieved, 'source': 'unit test', 'licence': 'CC0'}


def engine_item(path, file=None):
    return {'type': 'engine_data', 'path': path, 'file': file or path, 'attribution': 'test',
            'licence': 'CC0', 'retrieved': '2026-10-01T00:00:00+00:00', 'via': 'unit test'}


class Isolated:
    """Every test gets its own updates directory, trust list and overlay."""

    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp())
        self.enterContext(override_settings(
            UPDATES_ROOT=self.root / 'updates',
            ENGINE_DATA_OVERLAY=self.root / 'updates' / 'apk_engine' / 'current',
            TRUSTED_PUBLISHERS_FILE=self.root / 'updates' / 'trusted.json'))

    def trust(self, key=PUBLISHER_A, name='Test lab'):
        public = signing.public_key_bytes(key)
        return updates.trust_publisher(name, base64.b64encode(public).decode(),
                                       signing.fingerprint(public))

    def issues(self, text, **kwargs):
        return {code for code, _ in updates.assess(text, now=NOW, **kwargs).issues}


class FormatTests(SimpleTestCase):
    def test_a_built_bundle_parses_and_its_signature_verifies(self):
        text = make({'feed.txt': FEED}, items=[feed_item()])
        parsed = update_bundle.parse_and_verify_signature(text)
        self.assertEqual(parsed.fingerprint, fingerprint_of(PUBLISHER_A))
        self.assertEqual(parsed.manifest['sequence'], 1)
        self.assertEqual(len(parsed.payloads), 1)

    def test_editing_the_manifest_breaks_the_signature(self):
        envelope = json.loads(make({'feed.txt': FEED}, items=[feed_item()]))
        envelope['manifest_json'] = envelope['manifest_json'].replace('"sequence":1', '"sequence":9')
        with self.assertRaises(BadSignature):
            update_bundle.parse_and_verify_signature(json.dumps(envelope))

    def test_a_signature_over_a_case_package_is_not_valid_here(self):
        """The document-type prefix: one key cannot be made to sign across types."""
        envelope = json.loads(make({'feed.txt': FEED}, items=[feed_item()]))
        manifest_json = envelope['manifest_json'].encode()
        envelope['signature']['value'] = base64.b64encode(
            signing.sign(b'netforensiq.case-package/1\n', manifest_json, PUBLISHER_A)).decode()
        with self.assertRaises(BadSignature):
            update_bundle.parse_and_verify_signature(json.dumps(envelope))

    def test_garbage_is_a_clean_refusal(self):
        for text in ('', 'not json', '[]', '{"format": "other"}', '{"format": "%s"}' % update_bundle.FORMAT):
            with self.assertRaises(MalformedBundle):
                update_bundle.parse_and_verify_signature(text)

    def test_a_naive_timestamp_is_refused(self):
        with self.assertRaises(MalformedBundle):
            make({'feed.txt': FEED}, items=[feed_item()], expires='2027-01-01T00:00:00')

    def test_the_allow_lists_match_the_code_they_mirror(self):
        self.assertEqual(update_bundle.ENGINE_FILES, reference.UPDATABLE)
        self.assertEqual(set(update_bundle.IOC_FORMATS), set(IOCFeed.Format.values))

    def test_the_baselines_and_known_signers_are_not_updatable(self):
        for name in ('baselines.json', 'known_signers.json', 'sources.json'):
            self.assertNotIn(name, update_bundle.ENGINE_FILES)


class SizeLimitTests(SimpleTestCase):
    """Endless data."""

    def test_an_oversized_item_is_refused_at_build_time(self):
        with mock.patch.object(update_bundle, 'MAX_ITEM_BYTES', 10):
            with self.assertRaises(MalformedBundle):
                make({'feed.txt': FEED}, items=[feed_item()])

    def test_an_oversized_bundle_is_refused_before_it_is_parsed(self):
        with mock.patch.object(update_bundle, 'MAX_BUNDLE_BYTES', 100):
            with self.assertRaises(MalformedBundle):
                update_bundle.parse_and_verify_signature(make({'feed.txt': FEED}, items=[feed_item()]))

    def test_too_many_items_is_refused(self):
        items = [feed_item(name=f'feed {i}') for i in range(update_bundle.MAX_ITEMS + 1)]
        with self.assertRaises(MalformedBundle):
            make({'feed.txt': FEED}, items=items)


class TrustTests(Isolated, TestCase):
    """Arbitrary content: a bundle carrying a key is not a reason to trust the key."""

    def test_a_bundle_from_an_unknown_key_is_refused(self):
        text = make({'feed.txt': FEED}, items=[feed_item()])
        self.assertIn('untrusted', self.issues(text))
        with self.assertRaises(updates.BundleRefused):
            updates.apply_bundle(text, now=NOW)
        self.assertEqual(IOCFeed.objects.count(), 0)

    def test_trusting_requires_the_right_fingerprint(self):
        public = base64.b64encode(signing.public_key_bytes(PUBLISHER_A)).decode()
        with self.assertRaises(update_bundle.BundleError):
            updates.trust_publisher('Lab', public, 'ab' * 32)
        self.assertEqual(updates.trusted_publishers(), {})

    def test_a_fingerprint_may_be_typed_with_spaces_and_capitals(self):
        public = signing.public_key_bytes(PUBLISHER_A)
        typed = signing.display_fingerprint(signing.fingerprint(public)).upper()
        entry = updates.trust_publisher('Lab', base64.b64encode(public).decode(), typed)
        self.assertEqual(entry['fingerprint'], signing.fingerprint(public))

    def test_a_trusted_key_is_accepted_and_an_untrusted_one_still_is_not(self):
        self.trust(PUBLISHER_A)
        good = make({'feed.txt': FEED}, items=[feed_item()], key=PUBLISHER_A)
        other = make({'feed.txt': FEED}, items=[feed_item()], key=PUBLISHER_B)
        self.assertEqual(self.issues(good), set())
        self.assertIn('untrusted', self.issues(other))

    def test_removing_trust_stops_further_bundles(self):
        self.trust(PUBLISHER_A)
        updates.untrust_publisher(fingerprint_of(PUBLISHER_A))
        text = make({'feed.txt': FEED}, items=[feed_item()])
        self.assertIn('untrusted', self.issues(text))

    def test_a_corrupt_trust_file_is_an_error_not_an_empty_list(self):
        path = Path(updates.settings.TRUSTED_PUBLISHERS_FILE)
        path.parent.mkdir(parents=True)
        path.write_text('{not json')
        with self.assertRaises(update_bundle.BundleError):
            updates.trusted_publishers()


class RollbackTests(Isolated, TestCase):
    """Rollback and replay."""

    def setUp(self):
        super().setUp()
        self.trust(PUBLISHER_A)
        self.trust(PUBLISHER_B, 'Other lab')

    def apply(self, sequence, key=PUBLISHER_A, name='Test feed'):
        text = make({'feed.txt': FEED}, items=[feed_item(name=name)], sequence=sequence, key=key)
        return updates.apply_bundle(text, now=NOW)

    def test_the_same_sequence_cannot_be_applied_twice(self):
        self.apply(1)
        with self.assertRaises(updates.BundleRefused) as caught:
            self.apply(1)
        self.assertEqual(caught.exception.issues[0][0], 'rollback')
        self.assertEqual(IOCFeed.objects.count(), 1)

    def test_an_older_sequence_cannot_be_applied_after_a_newer_one(self):
        self.apply(5)
        with self.assertRaises(updates.BundleRefused):
            self.apply(3)
        self.assertEqual(UpdateBundle.objects.count(), 1)

    def test_a_newer_sequence_is_applied(self):
        self.apply(1)
        self.apply(2, name='Second feed')
        self.assertEqual(UpdateBundle.objects.count(), 2)
        self.assertEqual(IOCFeed.objects.count(), 2)

    def test_sequences_are_counted_per_publisher(self):
        self.apply(7, key=PUBLISHER_A)
        self.apply(1, key=PUBLISHER_B, name='Other feed')
        self.assertEqual(UpdateBundle.objects.count(), 2)

    def test_the_database_itself_refuses_a_duplicate_application(self):
        """Two operators racing: the constraint, not the check before it, is what holds."""
        row = self.apply(1)
        with self.assertRaises(IntegrityError), transaction.atomic():
            UpdateBundle.objects.create(
                publisher_fingerprint=row.publisher_fingerprint, sequence=1,
                bundle_sha256='0' * 64, created=NOW, expires=NOW)

    def test_a_fast_forward_by_the_key_holder_is_not_prevented(self):
        """
        Stated, not tested away. A key holder can publish sequence 10**9 and every
        honest bundle after it is then refused as a rollback. The defence is to
        stop trusting the key, not anything in the format.
        """
        self.apply(10 ** 9)
        with self.assertRaises(updates.BundleRefused):
            self.apply(2)
        updates.untrust_publisher(fingerprint_of(PUBLISHER_A))
        self.assertEqual(updates.trusted_publishers().get(fingerprint_of(PUBLISHER_A)), None)


class ExpiryTests(Isolated, TestCase):
    """Indefinite freeze."""

    def setUp(self):
        super().setUp()
        self.trust()

    def test_an_expired_bundle_is_refused(self):
        text = make({'feed.txt': FEED}, items=[feed_item()], expires=PAST,
                    created=(NOW - timedelta(days=30)).isoformat())
        self.assertIn('expired', self.issues(text))
        with self.assertRaises(updates.BundleRefused):
            updates.apply_bundle(text, now=NOW)

    def test_applying_after_expiry_needs_a_flag_and_is_recorded(self):
        text = make({'feed.txt': FEED}, items=[feed_item()], expires=PAST,
                    created=(NOW - timedelta(days=30)).isoformat())
        row = updates.apply_bundle(text, now=NOW, allow_expired=True)
        self.assertTrue(row.applied_after_expiry)

    def test_a_bundle_that_expires_before_it_was_created_is_malformed(self):
        text = make({'feed.txt': FEED}, items=[feed_item()], expires=PAST, created=SOON)
        self.assertIn('bad-time', self.issues(text))


class ContentTests(Isolated, TestCase):
    """Mix-and-match and wrong content installed."""

    def setUp(self):
        super().setUp()
        self.trust()

    def test_a_swapped_payload_is_refused(self):
        envelope = json.loads(make({'feed.txt': FEED}, items=[feed_item()]))
        envelope['payloads']['item1'] = base64.b64encode(b'203.0.113.99\n').decode()
        self.assertIn('payload-mismatch', self.issues(json.dumps(envelope)))

    def test_a_missing_payload_is_refused(self):
        envelope = json.loads(make({'feed.txt': FEED}, items=[feed_item()]))
        envelope['payloads'] = {}
        self.assertIn('missing-payload', self.issues(json.dumps(envelope)))

    def test_a_file_an_update_may_not_replace_is_refused(self):
        for name in ('baselines.json', 'known_signers.json', 'sources.json', '../escape.json',
                     '/etc/passwd'):
            text = make({'x': b'{}'}, items=[engine_item('x', file=name)])
            self.assertIn('not-updatable', self.issues(text), name)

    def test_an_unknown_item_type_is_refused(self):
        envelope = json.loads(make({'feed.txt': FEED}, items=[feed_item()]))
        manifest = json.loads(envelope['manifest_json'])
        manifest['items'][0]['type'] = 'shell_command'
        # re-sign, as a key holder could: the allow-list is what refuses it
        manifest_json = json.dumps(manifest, sort_keys=True, separators=(',', ':'))
        envelope['manifest_json'] = manifest_json
        envelope['signature']['value'] = base64.b64encode(
            signing.sign(update_bundle.CONTEXT, manifest_json.encode(), PUBLISHER_A)).decode()
        self.assertIn('unknown-type', self.issues(json.dumps(envelope)))

    def test_a_feed_in_an_unknown_format_is_refused(self):
        text = make({'feed.txt': FEED}, items=[feed_item(fmt='executable')])
        self.assertIn('bad-format', self.issues(text))

    def test_a_feed_dated_in_the_future_is_refused(self):
        text = make({'feed.txt': FEED}, items=[feed_item(retrieved='2030-01-01')])
        self.assertIn('future-date', self.issues(text))

    def test_engine_data_that_is_not_valid_json_is_refused(self):
        text = make({'s.json': b'not json'}, items=[engine_item('s.json', 'stalkerware_indicators.json')])
        self.assertIn('bad-content', self.issues(text))

    def test_a_non_ascii_tld_list_is_refused(self):
        text = make({'t.txt': 'bücher\n'.encode()}, items=[engine_item('t.txt', 'tlds.txt')])
        self.assertIn('bad-content', self.issues(text))

    def test_all_problems_are_reported_not_only_the_first(self):
        text = make({'feed.txt': FEED}, items=[feed_item(fmt='executable', retrieved='2030-01-01')],
                    expires=PAST, created=(NOW - timedelta(days=30)).isoformat())
        found = self.issues(text)
        self.assertTrue({'bad-format', 'future-date', 'expired'} <= found, found)


class ApplyTests(Isolated, TestCase):
    def setUp(self):
        super().setUp()
        self.trust()

    def test_a_feed_is_imported_through_the_ordinary_importer_with_its_provenance(self):
        text = make({'feed.txt': FEED}, items=[feed_item()])
        row = updates.apply_bundle(text, now=NOW, actor='alice')
        feed = IOCFeed.objects.get()
        self.assertEqual(feed.entry_count, 3)
        self.assertEqual(feed.file_sha256, hashlib.sha256(FEED).hexdigest())
        self.assertEqual(str(feed.retrieved_on), '2026-10-01')
        self.assertIn('signed update bundle #1', feed.notes)
        self.assertEqual((row.applied_by, row.sequence), ('alice', 1))
        self.assertEqual(row.contents[0]['sha256'], hashlib.sha256(FEED).hexdigest())

    def test_a_failing_item_applies_nothing_at_all(self):
        """Atomicity: a good feed beside an empty one must not leave the good one behind."""
        text = make({'good.txt': FEED, 'empty.txt': b'# nothing here\n'},
                    items=[feed_item('good.txt', 'Good'), feed_item('empty.txt', 'Empty')])
        with self.assertRaises(updates.BundleRefused):
            updates.apply_bundle(text, now=NOW)
        self.assertEqual(IOCFeed.objects.count(), 0)
        self.assertEqual(UpdateBundle.objects.count(), 0)
        self.assertFalse((updates._engine_root() / 'current').exists())

    def test_a_failed_application_leaves_no_staged_directory_behind(self):
        text = make({'t.txt': TLDS, 'empty.txt': b'# nothing\n'},
                    items=[engine_item('t.txt', 'tlds.txt'), feed_item('empty.txt', 'Empty')])
        with self.assertRaises(updates.BundleRefused):
            updates.apply_bundle(text, now=NOW)
        root = updates._engine_root()
        self.assertEqual([p.name for p in root.iterdir()] if root.exists() else [], [])

    def test_engine_data_is_staged_and_the_link_switched(self):
        text = make({'s.json': STALKERWARE}, items=[engine_item('s.json', 'stalkerware_indicators.json')])
        updates.apply_bundle(text, now=NOW)
        current = updates._engine_root() / 'current'
        self.assertTrue(current.is_symlink())
        self.assertEqual((current / 'stalkerware_indicators.json').read_bytes(), STALKERWARE)
        sources = json.loads((current / 'sources.json').read_text())
        self.assertIn('signed update bundle #1', sources['stalkerware_indicators.json']['via'])
        self.assertEqual(sources['stalkerware_indicators.json']['sha256'],
                         hashlib.sha256(STALKERWARE).hexdigest())

    def test_a_later_bundle_keeps_what_an_earlier_one_supplied(self):
        updates.apply_bundle(make({'s.json': STALKERWARE}, sequence=1,
                                  items=[engine_item('s.json', 'stalkerware_indicators.json')]), now=NOW)
        updates.apply_bundle(make({'t.txt': TLDS}, sequence=2,
                                  items=[engine_item('t.txt', 'tlds.txt')]), now=NOW)
        current = updates._engine_root() / 'current'
        self.assertEqual((current / 'stalkerware_indicators.json').read_bytes(), STALKERWARE)
        self.assertEqual((current / 'tlds.txt').read_bytes(), TLDS)
        self.assertEqual(len(json.loads((current / 'sources.json').read_text())), 2)

    def test_a_dry_run_changes_nothing(self):
        text = make({'feed.txt': FEED}, items=[feed_item()])
        out = StringIO()
        path = self.root / 'b.json'
        path.write_text(text)
        call_command('import_update_bundle', str(path), '--dry-run', stdout=out)
        self.assertIn('All checks pass', out.getvalue())
        self.assertEqual(IOCFeed.objects.count(), 0)
        self.assertEqual(UpdateBundle.objects.count(), 0)

    def test_the_command_refuses_an_untrusted_bundle_and_says_why(self):
        updates.untrust_publisher(fingerprint_of(PUBLISHER_A))
        path = self.root / 'b.json'
        path.write_text(make({'feed.txt': FEED}, items=[feed_item()]))
        out = StringIO()
        with self.assertRaises(CommandError):
            call_command('import_update_bundle', str(path), stdout=out)
        self.assertIn('untrusted', out.getvalue())
        self.assertEqual(IOCFeed.objects.count(), 0)

    def test_the_trust_command_needs_the_fingerprint(self):
        public = base64.b64encode(signing.public_key_bytes(PUBLISHER_B)).decode()
        with self.assertRaises(CommandError):
            call_command('trust_publisher', '--name', 'x', '--public-key', public,
                         '--fingerprint', '00' * 32)
        call_command('trust_publisher', '--name', 'x', '--public-key', public,
                     '--fingerprint', signing.display_fingerprint(fingerprint_of(PUBLISHER_B)))
        self.assertIn(fingerprint_of(PUBLISHER_B), updates.trusted_publishers())


class EngineReadsTheOverlayTests(Isolated, TestCase):
    """The data an update supplies is the data the examination actually uses."""

    def test_the_overlay_replaces_updatable_files_and_nothing_else(self):
        overlay = self.root / 'overlay'
        overlay.mkdir()
        (overlay / 'tlds.txt').write_bytes(TLDS)
        (overlay / 'baselines.json').write_text('{"hostile": true}')
        (overlay / 'known_signers.json').write_text('{"hostile": true}')
        with mock.patch.dict(os.environ, {'APK_ENGINE_DATA_DIR': str(overlay)}):
            self.assertEqual(reference.data_path('tlds.txt'), str(overlay / 'tlds.txt'))
            self.assertEqual(reference.data_path('baselines.json'),
                             os.path.join(reference.PACKAGE_DATA_DIR, 'baselines.json'))
            self.assertEqual(reference.data_path('known_signers.json'),
                             os.path.join(reference.PACKAGE_DATA_DIR, 'known_signers.json'))

    def test_with_no_overlay_nothing_changes(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('APK_ENGINE_DATA_DIR', None)
            for name in reference.UPDATABLE + ('baselines.json',):
                self.assertEqual(reference.data_path(name),
                                 os.path.join(reference.PACKAGE_DATA_DIR, name))

    def test_the_web_process_hands_the_overlay_to_the_engine(self):
        from . import apk_runner

        captured = {}

        def fake_run(command, **kwargs):
            captured['env'] = kwargs['env']
            return subprocess.CompletedProcess(command, 1, b'', b'')

        with mock.patch.object(apk_runner.subprocess, 'run', fake_run):
            apk_runner.run_examination('/nonexistent.apk')
            self.assertNotIn('APK_ENGINE_DATA_DIR', captured['env'])
            overlay = Path(updates.settings.ENGINE_DATA_OVERLAY)
            overlay.mkdir(parents=True)
            apk_runner.run_examination('/nonexistent.apk')
            self.assertEqual(captured['env']['APK_ENGINE_DATA_DIR'], os.path.realpath(overlay))

    def test_the_real_engine_process_reports_the_updated_data(self):
        """End to end: apply a bundle, run the actual engine, read its provenance block."""
        from apk_engine.tests import factories

        self.trust()
        tlds = TLDS + b'zzfake\n'
        updates.apply_bundle(make({'t.txt': tlds}, items=[engine_item('t.txt', 'tlds.txt')]), now=NOW)
        apk = self.root / 'sample.apk'
        apk.write_bytes(factories.apk())

        def examine(overlay):
            env = {'PATH': os.environ.get('PATH', ''), 'PYTHONPATH': str(BACKEND)}
            if overlay:
                env['APK_ENGINE_DATA_DIR'] = os.path.realpath(updates.settings.ENGINE_DATA_OVERLAY)
            done = subprocess.run([sys.executable, '-m', 'apk_engine', 'examine', '--apk', str(apk)],
                                  capture_output=True, cwd=BACKEND, env=env, timeout=300)
            return json.loads(done.stdout)['reproduction']['reference_data_sha256']

        shipped = examine(False)
        updated = examine(True)
        self.assertEqual(updated['tlds.txt'], hashlib.sha256(tlds).hexdigest())
        self.assertNotEqual(updated['tlds.txt'], shipped['tlds.txt'])
        # everything not updatable is exactly what shipped
        for name in ('baselines.json', 'known_signers.json', 'exodus_trackers.json'):
            self.assertEqual(updated[name], shipped[name], name)


class PublisherToolTests(SimpleTestCase):
    def run_tool(self, *args, cwd=None):
        return subprocess.run([sys.executable, str(REPO / 'scripts' / 'make_update_bundle.py'), *args],
                              capture_output=True, text=True, cwd=cwd, timeout=120)

    def test_keygen_build_and_inspect(self):
        directory = Path(tempfile.mkdtemp())
        key = directory / 'k'
        done = self.run_tool('keygen', '--out', str(key))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(oct(key.stat().st_mode & 0o777), '0o600')
        self.assertIn('trust_publisher', done.stdout)

        (directory / 'feed.txt').write_bytes(FEED)
        (directory / 'spec.json').write_text(json.dumps({
            'publisher': 'Lab', 'sequence': 1, 'expires': '2036-01-01T00:00:00+00:00',
            'items': [feed_item('feed.txt')]}))
        built = self.run_tool('build', '--key', str(key), '--spec', str(directory / 'spec.json'),
                              '--out', str(directory / 'u.nfupd.json'))
        self.assertEqual(built.returncode, 0, built.stderr)
        looked = self.run_tool('inspect', str(directory / 'u.nfupd.json'))
        self.assertEqual(looked.returncode, 0, looked.stdout + looked.stderr)
        self.assertIn('signature valid', looked.stdout)

    def test_keygen_refuses_to_overwrite_a_key(self):
        directory = Path(tempfile.mkdtemp())
        key = directory / 'k'
        self.assertEqual(self.run_tool('keygen', '--out', str(key)).returncode, 0)
        before = key.read_text()
        again = self.run_tool('keygen', '--out', str(key))
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(key.read_text(), before)

    def test_a_spec_cannot_read_outside_its_directory(self):
        directory = Path(tempfile.mkdtemp())
        key = directory / 'k'
        self.run_tool('keygen', '--out', str(key))
        (directory / 'spec.json').write_text(json.dumps({
            'publisher': 'x', 'sequence': 1, 'expires': '2036-01-01T00:00:00+00:00',
            'items': [feed_item('../../../../etc/hostname')]}))
        built = self.run_tool('build', '--key', str(key), '--spec', str(directory / 'spec.json'),
                              '--out', str(directory / 'u.json'))
        self.assertNotEqual(built.returncode, 0)
        self.assertFalse((directory / 'u.json').exists())

    def test_inspect_flags_a_tampered_bundle(self):
        directory = Path(tempfile.mkdtemp())
        key = directory / 'k'
        self.run_tool('keygen', '--out', str(key))
        (directory / 'feed.txt').write_bytes(FEED)
        (directory / 'spec.json').write_text(json.dumps({
            'publisher': 'Lab', 'sequence': 1, 'expires': '2036-01-01T00:00:00+00:00',
            'items': [feed_item('feed.txt')]}))
        self.run_tool('build', '--key', str(key), '--spec', str(directory / 'spec.json'),
                      '--out', str(directory / 'u.json'))
        envelope = json.loads((directory / 'u.json').read_text())
        envelope['manifest_json'] = envelope['manifest_json'].replace('"sequence":1', '"sequence":2')
        (directory / 'bad.json').write_text(json.dumps(envelope))
        looked = self.run_tool('inspect', str(directory / 'bad.json'))
        self.assertNotEqual(looked.returncode, 0)
        self.assertIn('bad-signature', looked.stderr + looked.stdout)
