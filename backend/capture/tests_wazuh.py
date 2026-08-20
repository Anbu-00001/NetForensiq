"""
The shipped Wazuh integration, checked against what we actually emit.

A decoder that has drifted from its emitter is worse than no decoder. It
installs cleanly, it matches nothing, and Wazuh reports zero NetForensiq
alerts — which looks exactly like a quiet network. So these tests read the XML
files we ship, pull the regexes and rule identifiers out of them, and run them
against real output from `to_syslog`.

They also hold the two claims the ruleset makes that could quietly become
false: that every rule the engine can emit is mapped to a Wazuh rule, and that
the ATT&CK identifiers in the ruleset agree with `attack_mapping.py` — because
if the platform's own ATT&CK view and the SOC's disagree, at least one of them
is lying to somebody.
"""

import re
from pathlib import Path
from xml.etree import ElementTree

from django.test import TestCase

from .attack_mapping import UNMAPPED, classify
from .detection import RULE_IDS
from .models import CaptureSession, Detection, Flow
from .siem import to_cef, to_syslog

WAZUH = Path(__file__).resolve().parents[2] / 'integrations' / 'wazuh'
DECODERS = WAZUH / 'decoders' / 'netforensiq_decoders.xml'
RULES = WAZUH / 'rules' / 'netforensiq_rules.xml'


def _parse(path):
    """
    Wazuh's files are XML fragments — several roots, no document element.

    Wrapped rather than "fixed": that shape is what Wazuh itself expects, and
    rewriting our files to be single-rooted so a parser is happy would ship
    something Wazuh will not load.
    """
    return ElementTree.fromstring(f'<root>{path.read_text()}</root>')


class WazuhDecoderTests(TestCase):
    def setUp(self):
        from datetime import datetime, timedelta, timezone as tz

        self.session = CaptureSession.objects.create(
            name='wazuh', source_type='pcap', state='completed',
            home_net='10.0.0.0/24',
        )
        start = datetime(2026, 2, 1, 8, 0, 0, tzinfo=tz.utc)
        self.flow = Flow.objects.create(
            session=self.session, src_ip='10.0.0.5', dst_ip='198.51.100.9',
            src_port=51001, dst_port=443, protocol='TCP',
            initiator_ip='10.0.0.5', initiator_confirmed=True,
            bytes_sent=900_000, bytes_received=1_200,
            first_seen=start, last_seen=start + timedelta(minutes=3),
        )

    def _finding(self, rule_id, severity='high', title='Something happened'):
        return Detection.objects.create(
            session=self.session, flow=self.flow, rule_id=rule_id,
            title=title, category='c2', severity=severity,
            rationale='r', subject_ip='10.0.0.5',
        )

    @staticmethod
    def _cef_regex():
        root = _parse(DECODERS)
        for decoder in root.findall('decoder'):
            if decoder.get('name') == 'netforensiq-cef':
                return decoder.find('regex').text
        raise AssertionError('netforensiq-cef decoder not found')

    def test_the_shipped_regex_decodes_our_real_output(self):
        pattern = re.compile(self._cef_regex())

        for rule_id in RULE_IDS:
            line = to_syslog(self._finding(rule_id), observer='forensics-01')
            match = pattern.search(line)
            self.assertIsNotNone(
                match, f'the shipped Wazuh regex does not match {rule_id}')

            vendor, product, _version, decoded_rule, title, cef_sev, severity = \
                match.groups()
            self.assertEqual(vendor, 'NetForensiq')
            self.assertEqual(product, 'PacketForensics')
            self.assertEqual(decoded_rule, rule_id)
            self.assertEqual(title, 'Something happened')
            self.assertTrue(cef_sev.isdigit())
            self.assertEqual(severity, 'high')

    def test_a_pipe_in_the_title_does_not_shift_every_later_field(self):
        r"""
        CEF escapes a literal pipe inside a header field as `\|`. A naive
        `[^|]*` stops at the escape and reads the severity out of the title,
        which is the classic way a CEF parser reports the wrong event.
        """
        pattern = re.compile(self._cef_regex())
        finding = self._finding('C2_BEACON_PERIODIC',
                                title='Callback to host|A every ~45s')

        match = pattern.search(to_syslog(finding))
        self.assertIsNotNone(match)
        self.assertEqual(match.group(4), 'C2_BEACON_PERIODIC')
        self.assertEqual(match.group(5), r'Callback to host\|A every ~45s')
        self.assertTrue(match.group(6).isdigit())

    def test_the_severity_word_the_rules_key_off_is_always_present(self):
        pattern = re.compile(self._cef_regex())
        for severity in ('low', 'medium', 'high', 'critical'):
            finding = self._finding('RECON_PORT_SCAN', severity=severity)
            self.assertEqual(
                pattern.search(to_cef(finding)).group(7), severity)


class WazuhRulesetTests(TestCase):
    @staticmethod
    def _rules():
        root = _parse(RULES)
        return root.find('group').findall('rule')

    def test_every_rule_the_engine_can_emit_is_mapped(self):
        """
        A finding with no Wazuh rule still alerts — the severity rules catch
        it — but it arrives without its ATT&CK identifier and without a
        sentence a SOC analyst can read. This test is what stops a rule added
        next month from silently degrading the integration.
        """
        matched = {
            rule.find('field').text.strip('^$')
            for rule in self._rules()
            if rule.find('field') is not None
            and rule.find('field').get('name') == 'nf_rule'
        }
        self.assertEqual(
            set(RULE_IDS) - matched, set(),
            'these detections have no Wazuh rule of their own',
        )

    def test_rule_ids_stay_inside_wazuhs_user_range(self):
        for rule in self._rules():
            self.assertGreaterEqual(int(rule.get('id')), 100000)
            self.assertLess(int(rule.get('id')), 120000)

    def test_no_rule_asks_wazuh_for_active_response_severity(self):
        """
        Wazuh treats 13-15 as attack-in-progress. A forensic tool reading a
        capture is making a claim about the past, and a claim about the past
        must not trigger an automated block.
        """
        for rule in self._rules():
            self.assertLessEqual(int(rule.get('level')), 12, rule.get('id'))

    def test_the_attack_ids_agree_with_our_own_mapping(self):
        """
        If Wazuh's ATT&CK coverage view and the platform's own disagree, at
        least one of them is misinforming somebody.
        """
        session = CaptureSession.objects.create(
            name='x', source_type='pcap', state='completed')

        for rule in self._rules():
            field = rule.find('field')
            mitre = rule.find('mitre')
            if field is None or field.get('name') != 'nf_rule':
                continue
            rule_id = field.text.strip('^$')

            finding = Detection(
                session=session, rule_id=rule_id, title='t', category='c',
                severity='high', rationale='r', subject_ip='10.0.0.5',
                evidence={},
            )
            ours = {t['id'] for t in classify(finding)}
            theirs = ({node.text for node in mitre.findall('id')}
                      if mitre is not None else set())

            if rule_id in UNMAPPED:
                self.assertEqual(
                    theirs, set(),
                    f'{rule_id} maps to no technique here but Wazuh claims one',
                )
            else:
                self.assertEqual(
                    theirs, ours,
                    f'{rule_id}: Wazuh says {theirs}, attack_mapping says {ours}',
                )
