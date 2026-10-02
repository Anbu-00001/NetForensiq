# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The release tool (scripts/make_release.py): signing, verification, the source
digest and the operating-system bill of materials.

What needs Docker and the network — building the image, the Python and npm bills
of materials — was run by hand against a real image (research/165). Everything
that decides whether a release *verifies* is here, and runs without either.
"""
import base64
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.test import SimpleTestCase

from . import signing

REPO = Path(__file__).resolve().parents[2]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, REPO / 'scripts' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = _load('make_release')
tree = _load('tree_digest')

KEY = Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32)
OTHER = Ed25519PrivateKey.from_private_bytes(bytes([6]) * 32)


def fingerprint(key):
    return signing.fingerprint(signing.public_key_bytes(key))


class ReleaseDir(SimpleTestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.files = {'netforensiq-1.0.tar.gz': b'archive bytes', 'sbom.cdx.json': b'{"bom": 1}',
                      'nfverify.html': b'<html>'}
        for name, data in self.files.items():
            (self.dir / name).write_bytes(data)
        self.sign()

    def sign(self, key=KEY, source=None):
        manifest = release.build_manifest(
            version='1.0', artefacts={n: self.dir / n for n in self.files},
            source=source or {'commit': 'a' * 40, 'dirty': False, 'tree_sha256': 'b' * 64},
            facts={'image': {'docker_image_id': 'sha256:' + 'c' * 64}})
        (self.dir / 'release-1.0.json').write_text(release.sign_manifest(manifest, key))

    def verify(self, fp=None):
        ok, lines = release.verify_release(self.dir, fp)
        return ok, '\n'.join(lines)


class VerifyTests(ReleaseDir):
    def test_an_untouched_release_verifies(self):
        ok, text = self.verify()
        self.assertTrue(ok, text)
        self.assertEqual(text.count('[PASS]'), 4)  # signature + three artefacts

    def test_a_changed_artefact_is_caught(self):
        (self.dir / 'sbom.cdx.json').write_bytes(b'{"bom": 2}')
        ok, text = self.verify()
        self.assertFalse(ok)
        self.assertIn('sbom.cdx.json: does not match the signed SHA-256', text)

    def test_a_missing_artefact_is_caught(self):
        (self.dir / 'nfverify.html').unlink()
        ok, text = self.verify()
        self.assertFalse(ok)
        self.assertIn('nfverify.html: missing', text)

    def test_an_edited_manifest_breaks_the_signature(self):
        path = self.dir / 'release-1.0.json'
        envelope = json.loads(path.read_text())
        envelope['manifest_json'] = envelope['manifest_json'].replace('"version":"1.0"', '"version":"9.9"')
        path.write_text(json.dumps(envelope))
        ok, text = self.verify()
        self.assertFalse(ok)
        self.assertIn('signature does not match', text)

    def test_the_wrong_fingerprint_fails_and_the_right_one_passes(self):
        self.assertFalse(self.verify('ab' * 32)[0])
        ok, text = self.verify(signing.display_fingerprint(fingerprint(KEY)))
        self.assertTrue(ok, text)
        self.assertIn('matches the fingerprint you supplied', text)

    def test_a_forgery_signed_with_another_key_verifies_and_only_the_fingerprint_exposes_it(self):
        """The honest limit, as for case packages."""
        self.sign(key=OTHER)
        self.assertTrue(self.verify()[0])
        self.assertFalse(self.verify(signing.display_fingerprint(fingerprint(KEY)))[0])

    def test_a_file_in_the_directory_that_the_manifest_does_not_name_is_flagged_not_hidden(self):
        (self.dir / 'extra.bin').write_bytes(b'surprise')
        ok, text = self.verify()
        self.assertTrue(ok)
        self.assertIn('extra.bin: present but not named by the manifest', text)

    def test_a_signature_for_another_document_type_is_rejected(self):
        path = self.dir / 'release-1.0.json'
        envelope = json.loads(path.read_text())
        envelope['signature']['value'] = base64.b64encode(signing.sign(
            b'netforensiq.case-package/1\n', envelope['manifest_json'].encode(), KEY)).decode()
        path.write_text(json.dumps(envelope))
        self.assertFalse(self.verify()[0])

    def test_two_manifests_or_none_is_a_failure(self):
        (self.dir / 'release-2.0.json').write_text((self.dir / 'release-1.0.json').read_text())
        self.assertFalse(self.verify()[0])
        (self.dir / 'release-1.0.json').unlink()
        (self.dir / 'release-2.0.json').unlink()
        self.assertFalse(self.verify()[0])

    def test_garbage_is_a_failure_not_an_exception(self):
        (self.dir / 'release-1.0.json').write_text('not json')
        self.assertFalse(self.verify()[0])

    def test_a_dirty_build_is_labelled_in_the_output(self):
        self.sign(source={'commit': 'd' * 40, 'dirty': True, 'tree_sha256': 'e' * 64})
        self.assertIn('uncommitted changes (dirty)', self.verify()[1])

    def test_the_manifest_says_what_it_does_not_claim(self):
        manifest = json.loads(json.loads((self.dir / 'release-1.0.json').read_text())['manifest_json'])
        self.assertTrue(any('reproducible' in line for line in manifest['not_claimed']))


class TreeDigestTests(SimpleTestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        (self.base / 'a.txt').write_text('alpha')
        (self.base / 'sub').mkdir()
        (self.base / 'sub' / 'b.txt').write_text('beta')

    def digest(self, files=('a.txt', 'sub/b.txt')):
        return tree.tree_digest(files, self.base)

    def test_the_order_files_are_listed_in_does_not_matter(self):
        self.assertEqual(self.digest(('a.txt', 'sub/b.txt')), self.digest(('sub/b.txt', 'a.txt')))

    def test_timestamps_and_permissions_do_not_matter(self):
        before = self.digest()
        os.utime(self.base / 'a.txt', (1, 1))
        (self.base / 'a.txt').chmod(0o600)
        self.assertEqual(before, self.digest())

    def test_one_changed_byte_changes_the_digest(self):
        before = self.digest()
        (self.base / 'a.txt').write_text('alphb')
        self.assertNotEqual(before, self.digest())

    def test_the_same_content_under_another_path_is_a_different_tree(self):
        (self.base / 'c.txt').write_text('alpha')
        self.assertNotEqual(self.digest(('a.txt',)), self.digest(('c.txt',)))


class GitStateTests(SimpleTestCase):
    """The dirty-tree rule, against a throwaway repository — never the real one."""

    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.git('init', '-q')
        (self.repo / 'f.txt').write_text('one')
        self.git('add', 'f.txt')
        self.git('-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '-m', 'one')
        self.enterContext(mock.patch.object(release, 'REPO', self.repo))

    def git(self, *args):
        subprocess.run(['git', '-C', str(self.repo), *args], check=True, capture_output=True)

    def test_a_clean_tree_is_not_dirty_and_names_its_commit(self):
        state = release.source_state()
        self.assertFalse(state['dirty'])
        self.assertEqual(len(state['commit']), 40)
        self.assertEqual(state['tracked_files'], 1)

    def test_a_modified_tracked_file_makes_it_dirty_and_changes_the_digest(self):
        clean = release.source_state()
        (self.repo / 'f.txt').write_text('two')
        dirty = release.source_state()
        self.assertTrue(dirty['dirty'])
        self.assertNotEqual(clean['tree_sha256'], dirty['tree_sha256'])

    def test_an_untracked_file_also_counts_as_dirty(self):
        (self.repo / 'new.txt').write_text('x')
        self.assertTrue(release.source_state()['dirty'])

    def test_a_directory_that_is_not_a_checkout_is_refused(self):
        with mock.patch.object(release, 'REPO', Path(tempfile.mkdtemp())):
            with self.assertRaises(release.ReleaseError):
                release.source_state()


class OsBomTests(SimpleTestCase):
    def test_packages_become_purls_and_the_document_is_ordered(self):
        lines = ['zlib1g\t1:1.3.dfsg\tamd64', 'bash\t5.2.15\tamd64', '', 'broken-line-without-version']
        bom = release.os_sbom(lines, {'ID': 'debian', 'VERSION_ID': '13'}, 'netforensiq:1.0')
        self.assertEqual(bom['bomFormat'], 'CycloneDX')
        self.assertEqual(bom['specVersion'], release.SPEC_VERSION)
        self.assertEqual([c['name'] for c in bom['components']], ['bash', 'zlib1g'])
        self.assertTrue(all(c['purl'].startswith('pkg:deb/debian/') for c in bom['components']))
        self.assertIn('arch=amd64', bom['components'][0]['purl'])
        self.assertEqual(len({c['bom-ref'] for c in bom['components']}), 2)

    def test_the_same_input_gives_the_same_document(self):
        args = (['a\t1\tamd64', 'b\t2\tamd64'], {'ID': 'debian'}, 'img')
        self.assertEqual(json.dumps(release.os_sbom(*args)), json.dumps(release.os_sbom(*args)))


class KeygenTests(SimpleTestCase):
    def test_keygen_writes_a_private_file_and_refuses_to_overwrite(self):
        path = Path(tempfile.mkdtemp()) / 'k'
        args = mock.Mock(out=str(path))
        release.cmd_keygen(args)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        before = path.read_text()
        with self.assertRaises(release.ReleaseError):
            release.cmd_keygen(args)
        self.assertEqual(path.read_text(), before)

    def test_a_malformed_key_file_is_an_error(self):
        path = Path(tempfile.mkdtemp()) / 'k'
        path.write_text('not base64!')
        with self.assertRaises(release.ReleaseError):
            release.load_key(path)
