# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The deployment files and the documents that describe them, held to what was
measured (research/161).

Each test here pins a defect that shipped, was found by running the thing, and
could not have been found by reading it:

* an image that would not start under a plain `docker run`;
* a printed run command that started a container and published nothing;
* a compose command that silently lost its `--bind`.

None of these needs Docker: they read the files. They cannot prove a deployment
works — scripts/verify_airgap.sh and an actual `docker compose up` do that — but
they stop the specific mistakes from coming back unnoticed.
"""
import re
from pathlib import Path

from django.test import SimpleTestCase

REPO = Path(__file__).resolve().parents[2]

# Docker's default capability set, from
# https://docs.docker.com/engine/containers/run/ (runtime privilege and Linux
# capabilities). NET_ADMIN is deliberately absent: it is not granted by default.
DOCKER_DEFAULT_CAPS = {
    'cap_audit_write', 'cap_chown', 'cap_dac_override', 'cap_fowner',
    'cap_fsetid', 'cap_kill', 'cap_mknod', 'cap_net_bind_service',
    'cap_net_raw', 'cap_setfcap', 'cap_setgid', 'cap_setpcap', 'cap_setuid',
    'cap_sys_chroot',
}


def _read(relative):
    return (REPO / relative).read_text(encoding='utf-8')


def _search(pattern, text, flags=0):
    """re.search that fails the test, readably, instead of returning None."""
    match = re.search(pattern, text, flags)
    if match is None:
        raise AssertionError(f'pattern not found: {pattern!r}')
    return match


def _code_lines(relative):
    """
    Lines that would be executed or copied, with backslash continuations joined.

    In Markdown only fenced code blocks count: prose that *describes* a bad
    command (as the README does, to explain why the relay exists) is not a
    command someone will paste. Shell comments and `#` lines are skipped.
    """
    joined, pending = [], ''
    in_fence = False
    is_markdown = relative.endswith('.md')
    for raw in _read(relative).splitlines():
        line = raw.strip()
        if is_markdown:
            if line.startswith('```'):
                in_fence = not in_fence
                continue
            if not in_fence:
                continue
        if line.startswith('#'):
            continue
        if line.endswith('\\'):
            pending += line[:-1] + ' '
            continue
        joined.append(pending + line)
        pending = ''
    return joined


class DockerfileCapabilityTests(SimpleTestCase):
    def test_file_capabilities_with_the_effective_bit_are_in_dockers_default_set(self):
        """
        Python is a "capability-dumb" binary. With the effective bit set, the
        kernel refuses to exec it unless every permitted file capability can be
        granted (capabilities(7)). `cap_net_raw,cap_net_admin=eip` therefore
        made `docker run netforensiq` fail with
        `exec /usr/local/bin/python: operation not permitted`, because
        CAP_NET_ADMIN is not in Docker's default set.
        """
        found = False
        for line in _code_lines('Dockerfile'):
            for caps, flags in re.findall(r'setcap\s+(\S+?)=(\w+)', line):
                found = True
                if 'e' not in flags:
                    continue
                for cap in caps.split(','):
                    self.assertIn(
                        cap.lower(), DOCKER_DEFAULT_CAPS,
                        f'setcap {caps}={flags}: {cap} is not in Docker\'s default '
                        f'capability set, so the interpreter will not start under '
                        f'a plain `docker run`.')
        self.assertTrue(found, 'expected the Dockerfile to grant the capture capability')

    def test_the_documents_do_not_ask_for_net_admin(self):
        for relative in ('README.md', 'RUN_OFFLINE.md', 'docker-compose.yml',
                         'docker-compose.airgap.yml'):
            for line in _code_lines(relative):
                self.assertNotRegex(
                    line, r'(?i)(cap-add[= ]\s*NET_ADMIN|cap_add.*NET_ADMIN)',
                    f'{relative} asks for NET_ADMIN, which live capture does not need')


class AirgapComposeTests(SimpleTestCase):
    def setUp(self):
        self.text = '\n'.join(
            l for l in _read('docker-compose.airgap.yml').splitlines()
            if not l.strip().startswith('#'))

    def test_the_application_network_is_internal(self):
        self.assertRegex(self.text, r'(?ms)^networks:.*?inner:\s*\n\s*(#.*\n\s*)*internal:\s*true')

    def test_only_the_relay_publishes_a_port_and_only_on_loopback(self):
        ports = re.findall(r'^\s*ports:\s*\n((?:\s*-\s*.+\n)+)', self.text, re.M)
        self.assertEqual(len(ports), 1, 'exactly one service should publish a port')
        for entry in re.findall(r'-\s*"?([^"\n]+)"?', ports[0]):
            self.assertTrue(entry.startswith('127.0.0.1:'),
                            f'published on something other than loopback: {entry}')
        app = _search(r'(?ms)^  app:\n(.*?)^  gate:', self.text).group(1)
        self.assertNotIn('ports:', app, 'the application itself must not publish a port')

    def test_both_state_volumes_are_mounted(self):
        """Without /app/data the database and the evidence key vanish with the container."""
        self.assertIn(':/app/data', self.text)
        self.assertIn(':/app/evidence_store', self.text)

    def test_the_server_command_keeps_its_flags(self):
        """
        The first version used a YAML folded block with deeper-indented
        continuation lines. YAML keeps those newlines, the shell ended the
        command after `application`, and gunicorn started on its defaults —
        127.0.0.1, one worker, 30 s — with no error and a passing healthcheck.
        """
        command = _search(r'^\s*command:\s*(.+)$', self.text, re.M).group(1)
        self.assertNotIn(command.strip(), ('>', '|', '>-', '|-'),
                         'a block scalar command loses flags silently; use one line')
        for flag in ('--bind 0.0.0.0:8000', '--workers 3', '--timeout 1800'):
            self.assertIn(flag, command)

    def test_no_compose_file_uses_a_block_scalar_command(self):
        for relative in ('docker-compose.yml', 'docker-compose.airgap.yml'):
            for line in _read(relative).splitlines():
                self.assertNotRegex(line.strip(), r'^command:\s*[>|][-+]?\s*$',
                                    f'{relative}: block scalar command')

    def test_the_relay_image_is_the_one_the_save_script_carries(self):
        tag = _search(r'image:\s*(alpine/socat:\S+)', self.text).group(1)
        self.assertIn(tag.split('@')[0], _read('docker-compose.airgap.yml'))
        self.assertIn('alpine/socat', _read('scripts/save_airgap_images.sh'))


class PrintedCommandTests(SimpleTestCase):
    """
    `docker run --network none -p ...` starts a container and publishes
    nothing; `docker port` prints an empty line and a browser cannot connect.
    Docker does not warn. The printed command for the air-gapped single
    workstation did exactly this.
    """

    FILES = ('scripts/load_airgap_images.sh', 'README.md', 'RUN_OFFLINE.md')

    def test_no_documented_command_combines_network_none_with_a_published_port(self):
        for relative in self.FILES:
            for line in _code_lines(relative):
                if line.startswith(('>', '|')) or 'docker run' not in line:
                    continue
                if '--network none' in line or '--net none' in line:
                    self.assertNotRegex(
                        line, r'(\s-p\s|\s--publish[\s=])',
                        f'{relative}: publishes a port under --network none')

    def test_the_single_container_command_mounts_the_data_volume(self):
        script = _read('scripts/load_airgap_images.sh')
        block = script[script.index('docker run -d'):]
        self.assertIn('/app/data', block)
        self.assertIn('EVIDENCE_ENCRYPTION_KEY', block)
        self.assertNotIn('--rm', block.split('netforensiq_evidence')[0],
                         '--rm deletes anonymous volumes when the container stops')


class ClaimWordingTests(SimpleTestCase):
    def test_nothing_claims_construction_level_isolation_of_the_running_server(self):
        """
        "The running container needs no network, verified under --network none"
        was not what had been run: the server cannot publish a port under
        --network none, and RUN_OFFLINE.md says so. The claim is now about what
        the code does by default and what the compose network guarantees.
        """
        for relative in ('README.md', 'Dockerfile'):
            text = _read(relative)
            for phrase in ('The running container needs **no network**',
                           'Verified under `--network none`'):
                self.assertTrue(phrase not in text,
                                f'{relative} still says: {phrase}')

    def test_the_readme_does_not_promise_no_network_at_all(self):
        self.assertTrue('no network at all' not in _read('README.md'),
                        'README.md promises "no network at all"')


class ImageHygieneTests(SimpleTestCase):
    """
    A container image is carried across air gaps and shared. Until research/161
    s.5 the developer's real `.evidence.key` was copied into every image built
    from a working checkout, because `.dockerignore` excluded databases and the
    evidence store but not keys.
    """

    def test_dockerignore_excludes_keys(self):
        ignored = {line.strip() for line in _read('.dockerignore').splitlines()
                   if line.strip() and not line.strip().startswith('#')}
        for pattern in ('**/.evidence.key', '**/.signing.key', '**/*.key', '**/*.pem'):
            self.assertIn(pattern, ignored, f'.dockerignore does not exclude {pattern}')

    def test_dockerignore_still_excludes_databases_and_the_evidence_store(self):
        ignored = {line.strip() for line in _read('.dockerignore').splitlines()}
        for pattern in ('**/*.sqlite3', '**/evidence_store', '**/.env'):
            self.assertIn(pattern, ignored)

    def test_gitignore_excludes_the_signing_key(self):
        text = _read('.gitignore')
        self.assertIn('.signing.key', text)
