#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Build, sign and verify a NetForensiq release — run on a *connected* machine.

A laboratory that takes the software across an air gap has one question about
the file in its hand: is this what the author published? This produces what lets
it answer that offline: the image archive, a CycloneDX software bill of
materials for everything in it, and a signed manifest naming each artefact by
SHA-256 together with the exact state of the source it was built from.

    make_release.py keygen --out release.key
    make_release.py build  --version 1.0.0 --key release.key --out release/ [--image TAG]
    make_release.py verify release/ [--fingerprint "a1b2c3d4 ..."]

Needs Python, `cryptography`, Docker, and — for the bill of materials —
`cyclonedx-py` (`pip install cyclonedx-bom`, in any environment, not the project's)
and Node/npm for `@cyclonedx/cyclonedx-npm`. Set CYCLONEDX_PY to the executable if
it is not on PATH.

What is and is not claimed
--------------------------
* The manifest is signed with an Ed25519 key (context "netforensiq.release/1\\n").
  Anyone can sign a manifest with their own key; recipients must compare the key's
  fingerprint with one obtained another way, exactly as for case packages.
* **Not claimed: reproducible builds.** A Docker image built twice is not
  bit-identical. The signed manifest binds one specific archive (by SHA-256) to a
  version; it does not let anyone rebuild that archive. What *is* reproducible is
  the source identity: `source.tree_sha256` is a digest over the repository's
  tracked files that anyone with a checkout can recompute with
  scripts/tree_digest.py.
* A build from a working tree with uncommitted changes is refused unless
  `--allow-dirty`, and then the manifest says `dirty: true`. A release that cannot
  be traced to a commit is not much of a release.
* The image's own identifier is recorded, but it is not relied upon: Docker
  documents that the identifier's meaning depends on the image store in use, and
  this was not tested across stores. The archive's SHA-256 is what a recipient
  checks.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'backend'))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from evidence import signing  # noqa: E402

FORMAT = 'netforensiq.release/1'
MANIFEST_SCHEMA = 'netforensiq.release-manifest/1'
CONTEXT = b'netforensiq.release/1\n'
SPEC_VERSION = '1.6'


class ReleaseError(Exception):
    pass


sys.path.insert(0, str(Path(__file__).resolve().parent))
from tree_digest import sha256_file, tree_digest  # noqa: E402  (standalone, so recipients can run it too)


def git(*args):
    return subprocess.run(['git', '-C', str(REPO), *args], capture_output=True, text=True, timeout=60)


def source_state():
    """What the build is made from. Read-only git commands; nothing is written."""
    head = git('rev-parse', 'HEAD')
    if head.returncode != 0:
        raise ReleaseError('this is not a git checkout: a release must be traceable to a commit')
    listing = git('ls-files', '-z')
    files = [f for f in listing.stdout.split('\0') if f and (REPO / f).is_file()]
    dirty = bool(git('status', '--porcelain').stdout.strip())
    return {
        'commit': head.stdout.strip(),
        'dirty': dirty,
        'tracked_files': len(files),
        'tree_sha256': tree_digest(files, REPO),
        'tree_digest_command': 'python scripts/tree_digest.py',
    }


# ───────────────────── bills of materials ─────────────────────

def cyclonedx_py():
    exe = os.environ.get('CYCLONEDX_PY') or shutil.which('cyclonedx-py')
    if not exe:
        raise ReleaseError('cyclonedx-py is not installed: pip install cyclonedx-bom '
                           '(anywhere; or set CYCLONEDX_PY to the executable)')
    return exe


def purl(kind, namespace, name, version, **qualifiers):
    text = f'pkg:{kind}/' + (f'{namespace}/' if namespace else '') + f'{name}@{version}'
    if qualifiers:
        text += '?' + '&'.join(f'{k}={v}' for k, v in sorted(qualifiers.items()))
    return text


def os_sbom(dpkg_lines, os_release, image_name):
    """
    A CycloneDX document for the image's operating-system packages.

    `dpkg_lines` are `package<TAB>version<TAB>architecture` lines from
    `dpkg-query -W`. Built directly rather than through a tool because the
    information is already structured and a tool would add a dependency; it is
    checked against CycloneDX's own JSON schema by scripts/check_sbom.py, as are the others.
    """
    distro = os_release.get('ID', 'debian')
    components = []
    for line in dpkg_lines:
        parts = line.rstrip('\n').split('\t')
        if len(parts) < 2 or not parts[0]:
            continue
        name, version = parts[0], parts[1]
        arch = parts[2] if len(parts) > 2 else ''
        ref = purl('deb', distro, name, version, **({'arch': arch} if arch else {}),
                   distro=f'{distro}-{os_release.get("VERSION_ID", "")}'.rstrip('-'))
        components.append({'type': 'library', 'bom-ref': ref, 'name': name, 'version': version,
                           'purl': ref})
    return {
        'bomFormat': 'CycloneDX', 'specVersion': SPEC_VERSION, 'version': 1,
        'metadata': {
            'component': {'type': 'container', 'name': image_name, 'bom-ref': f'image:{image_name}'},
            'properties': [{'name': 'netforensiq:scope', 'value': 'operating-system packages'}],
        },
        'components': sorted(components, key=lambda c: (c['name'], c['version'])),
    }


def run(command, **kwargs):
    done = subprocess.run(command, capture_output=True, **kwargs)
    if done.returncode != 0:
        tail = (done.stderr or b'').decode('utf-8', 'replace').strip().splitlines()[-3:]
        raise ReleaseError(f'{" ".join(map(str, command[:3]))}… failed: {" | ".join(tail)}')
    return done.stdout


def make_sboms(image, out):
    sboms = {}
    exe = cyclonedx_py()

    freeze = run(['docker', 'run', '--rm', '--entrypoint', 'python', image, '-m', 'pip', 'freeze'])
    python = out / 'sbom-python.cdx.json'
    run([exe, 'requirements', '-', '--sv', SPEC_VERSION, '--of', 'JSON', '-o', str(python),
         '--validate'], input=freeze)
    sboms['sbom-python.cdx.json'] = python

    dpkg = run(['docker', 'run', '--rm', '--entrypoint', 'dpkg-query', image, '-W',
                '-f', '${binary:Package}\t${Version}\t${Architecture}\n']).decode()
    release = run(['docker', 'run', '--rm', '--entrypoint', 'cat', image, '/etc/os-release']).decode()
    parsed = dict(line.split('=', 1) for line in release.splitlines() if '=' in line)
    parsed = {k: v.strip('"') for k, v in parsed.items()}
    os_file = out / 'sbom-os.cdx.json'
    os_file.write_text(json.dumps(os_sbom(dpkg.splitlines(), parsed, image), indent=1) + '\n')
    sboms['sbom-os.cdx.json'] = os_file

    for name, folder, extra in (('sbom-frontend.cdx.json', 'frontend', ['--omit', 'dev']),
                                ('sbom-verifier.cdx.json', 'verifier', [])):
        target = out / name
        run(['npx', '--yes', '@cyclonedx/cyclonedx-npm@6.0.1', '--spec-version', SPEC_VERSION,
             '--output-format', 'JSON', '--output-file', str(target), *extra],
            cwd=REPO / folder)
        sboms[name] = target

    # Every document is checked against CycloneDX's schema, with the Python of the
    # environment the generator lives in (it carries the validator).
    checker = Path(exe).resolve().parent / 'python'
    verdict = subprocess.run([str(checker if checker.exists() else sys.executable),
                              str(Path(__file__).resolve().parent / 'check_sbom.py'),
                              *map(str, sboms.values())], capture_output=True, text=True)
    print(verdict.stdout.strip())
    if verdict.returncode != 0:
        raise ReleaseError('a bill of materials failed schema validation: ' + verdict.stdout[-300:])
    return sboms


# ───────────────────────────── manifest ─────────────────────────────

def build_manifest(*, version, artefacts, source, facts, now=None):
    return {
        'schema': MANIFEST_SCHEMA,
        'product': 'NetForensiq',
        'version': version,
        'built_at': (now or datetime.now(timezone.utc)).isoformat(),
        'source': source,
        'artefacts': [{'name': name, 'sha256': sha256_file(path), 'size': Path(path).stat().st_size}
                      for name, path in sorted(artefacts.items())],
        'facts': facts,
        'not_claimed': ['reproducible builds: the archive cannot be rebuilt bit for bit',
                        'that the signing key belongs to any particular person or laboratory'],
    }


def sign_manifest(manifest, private_key):
    manifest_json = json.dumps(manifest, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    public = signing.public_key_bytes(private_key)
    value = signing.sign(CONTEXT, manifest_json.encode('utf-8'), private_key)
    return json.dumps({
        'format': FORMAT, 'manifest_json': manifest_json,
        'signature': {'algorithm': 'ed25519', 'public_key': base64.b64encode(public).decode(),
                      'key_fingerprint': signing.fingerprint(public),
                      'value': base64.b64encode(value).decode()},
    }, indent=1, ensure_ascii=False) + '\n'


def verify_release(directory, expected_fingerprint=None):
    """
    Check a release directory. Returns (ok, lines). Never raises on bad input.
    """
    directory = Path(directory)
    lines, ok = [], True

    def say(level, text):
        nonlocal ok
        if level == 'FAIL':
            ok = False
        lines.append(f'[{level}] {text}')

    manifests = sorted(directory.glob('release-*.json'))
    if len(manifests) != 1:
        say('FAIL', f'expected exactly one release-*.json in {directory}, found {len(manifests)}')
        return False, lines
    try:
        envelope = json.loads(manifests[0].read_text())
        sig = envelope['signature']
        public = base64.b64decode(sig['public_key'], validate=True)
        value = base64.b64decode(sig['value'], validate=True)
        manifest_json = envelope['manifest_json']
        if envelope.get('format') != FORMAT or sig.get('algorithm') != 'ed25519':
            raise ValueError('wrong format or algorithm')
    except (OSError, ValueError, KeyError, TypeError):
        say('FAIL', f'{manifests[0].name} is not a {FORMAT} file')
        return False, lines

    fingerprint = signing.fingerprint(public)
    if not signing.verify(CONTEXT, manifest_json.encode('utf-8'), value, public):
        say('FAIL', 'the signature does not match the manifest')
        return False, lines
    say('PASS', 'the manifest is exactly as it was signed')

    if expected_fingerprint:
        from evidence.case_package import normalise_fingerprint
        if normalise_fingerprint(expected_fingerprint) == fingerprint:
            say('PASS', 'the signing key matches the fingerprint you supplied')
        else:
            say('FAIL', 'the signing key does NOT match the fingerprint you supplied')
    else:
        say('INFO', f'signed by key {signing.display_fingerprint(fingerprint)}; compare it with '
                    f'one you obtained separately')

    manifest = json.loads(manifest_json)
    for artefact in manifest.get('artefacts', []):
        path = directory / artefact['name']
        if not path.is_file():
            say('FAIL', f'{artefact["name"]}: missing')
        elif sha256_file(path) != artefact['sha256']:
            say('FAIL', f'{artefact["name"]}: does not match the signed SHA-256')
        else:
            say('PASS', f'{artefact["name"]}: SHA-256 matches ({artefact["size"]:,} bytes)')
    listed = {a['name'] for a in manifest.get('artefacts', [])}
    for extra in sorted(p.name for p in directory.iterdir()
                        if p.is_file() and p.name not in listed and not p.name.startswith('release-')
                        and p.name != 'SHA256SUMS'):
        say('INFO', f'{extra}: present but not named by the manifest')
    source = manifest.get('source', {})
    say('INFO', f'built from commit {source.get("commit", "?")[:12]}'
                f'{" with uncommitted changes (dirty)" if source.get("dirty") else ""}; '
                f'tree digest {str(source.get("tree_sha256", "?"))[:16]}…')
    return ok, lines


# ───────────────────────────── commands ─────────────────────────────

def load_key(path):
    try:
        seed = base64.b64decode(Path(path).read_text().strip(), validate=True)
    except (OSError, ValueError) as exc:
        raise ReleaseError(f'cannot read the key {path}: {exc}')
    if len(seed) != signing.SEED_BYTES:
        raise ReleaseError(f'{path} does not hold a {signing.SEED_BYTES}-byte key')
    return Ed25519PrivateKey.from_private_bytes(seed)


def cmd_keygen(args):
    seed = os.urandom(signing.SEED_BYTES)
    try:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ReleaseError(f'{args.out} already exists. Refusing to overwrite a signing key.')
    with os.fdopen(fd, 'w') as handle:
        handle.write(base64.b64encode(seed).decode() + '\n')
    public = signing.public_key_bytes(Ed25519PrivateKey.from_private_bytes(seed))
    print(f'Wrote {args.out} (mode 0600). Keep it private and back it up elsewhere.')
    print('Publish this fingerprint where people will find it independently of the releases —')
    print('the README, a signed commit, a notice — so they can check who signed:')
    print(f'  {signing.display_fingerprint(signing.fingerprint(public))}')


def cmd_build(args):
    key = load_key(args.key)
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise ReleaseError(f'{out} is not empty')
    out.mkdir(parents=True, exist_ok=True)

    source = source_state()
    if source['dirty'] and not args.allow_dirty:
        raise ReleaseError('the working tree has uncommitted changes, so this build cannot be traced '
                           'to a commit. Commit first, or pass --allow-dirty (the manifest will say so).')

    image = args.image or f'netforensiq:{args.version}'
    if not args.image:
        print(f'building {image} …')
        run(['docker', 'build', '-t', image, str(REPO)])
    inspected = json.loads(run(['docker', 'image', 'inspect', image]))[0]

    archive = out / f'netforensiq-{args.version}.tar.gz'
    print(f'saving {archive.name} …')
    with open(archive, 'wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0, compresslevel=6) as zipped:
        saver = subprocess.Popen(['docker', 'save', image], stdout=subprocess.PIPE)
        for block in iter(lambda: saver.stdout.read(1024 * 1024), b''):
            zipped.write(block)
        if saver.wait() != 0:
            raise ReleaseError('docker save failed')

    artefacts = {archive.name: archive}
    if not args.no_sbom:
        print('writing software bills of materials …')
        artefacts.update(make_sboms(image, out))
    for relative in ('verifier/dist/nfverify.html', 'validation/VALIDATION_REPORT.md',
                     'validation/results.json', 'docker-compose.airgap.yml'):
        copy = out / Path(relative).name
        shutil.copy2(REPO / relative, copy)
        artefacts[copy.name] = copy

    facts = {
        'image': {'reference': image, 'docker_image_id': inspected['Id'],
                  'architecture': inspected.get('Architecture'), 'os': inspected.get('Os'),
                  'note': 'recorded for reference only; check the archive SHA-256'},
        'baselines_sha256': sha256_file(REPO / 'backend/apk_engine/data/baselines.json'),
        'rule_base_rates_sha256': sha256_file(REPO / 'backend/capture/data/rule_base_rates.json'),
        'verifier_page_sha256': sha256_file(REPO / 'verifier/dist/nfverify.html'),
    }
    manifest = build_manifest(version=args.version, artefacts=artefacts, source=source, facts=facts)
    (out / f'release-{args.version}.json').write_text(sign_manifest(manifest, key))
    with open(out / 'SHA256SUMS', 'w') as handle:
        for item in manifest['artefacts']:
            handle.write(f'{item["sha256"]}  {item["name"]}\n')

    ok, lines = verify_release(out)
    print('\n'.join(lines))
    print(f'\nWrote {out}/ . Verify elsewhere with: make_release.py verify {out} --fingerprint "..."')
    return 0 if ok else 1


def cmd_verify(args):
    ok, lines = verify_release(args.directory, args.fingerprint)
    print('\n'.join(lines))
    print('\nResult:', 'verified' if ok else 'DOES NOT VERIFY')
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description=(__doc__ or '').split('\n\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('keygen'); p.add_argument('--out', required=True); p.set_defaults(fn=cmd_keygen)
    p = sub.add_parser('build')
    p.add_argument('--version', required=True); p.add_argument('--key', required=True)
    p.add_argument('--out', required=True); p.add_argument('--image')
    p.add_argument('--allow-dirty', action='store_true'); p.add_argument('--no-sbom', action='store_true')
    p.set_defaults(fn=cmd_build)
    p = sub.add_parser('verify'); p.add_argument('directory'); p.add_argument('--fingerprint')
    p.set_defaults(fn=cmd_verify)
    args = parser.parse_args()
    try:
        sys.exit(args.fn(args) or 0)
    except ReleaseError as exc:
        sys.exit(f'error: {exc}')


if __name__ == '__main__':
    main()
