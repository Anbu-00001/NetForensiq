"""
Tests over attack scenario reconstruction.

The interesting assertions here are the negative ones. It is easy to write a
kill-chain view that produces a satisfying story; the failure mode is that it
produces a satisfying story out of evidence that does not support one. So most
of what follows checks that the module refuses to tidy up — that unmappable
findings survive with their reason attached, that the ten tactics network
capture cannot see are always named, and that a sequence contradicted by the
packet clock says so instead of being sorted into shape.
"""

from datetime import datetime, timedelta, timezone

from django.test import TestCase

from .models import CaptureSession, Detection, Flow
from .scenario import TACTIC_ORDER, UNOBSERVABLE, reconstruct

T0 = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)


class ScenarioTests(TestCase):
    def setUp(self):
        self.session = CaptureSession.objects.create(
            name='scenario-fixture', source_type='pcap', state='completed',
            home_net='10.0.0.0/24',
        )

    def _flow(self, minutes, src='10.0.0.5', dst='198.51.100.7'):
        start = T0 + timedelta(minutes=minutes)
        return Flow.objects.create(
            session=self.session, src_ip=src, dst_ip=dst,
            src_port=51000, dst_port=443, protocol='TCP',
            initiator_ip=src, initiator_confirmed=True,
            first_seen=start, last_seen=start + timedelta(seconds=30),
        )

    def _finding(self, rule_id, severity='high', subject='10.0.0.5',
                 flow=None, evidence=None, title=None):
        return Detection.objects.create(
            session=self.session, flow=flow, rule_id=rule_id,
            title=title or rule_id.replace('_', ' ').title(),
            category='c2', severity=severity, rationale='fixture',
            evidence=evidence or {}, subject_ip=subject,
        )

    # ── ordering ────────────────────────────────────────────────────────────

    def test_stages_come_out_in_attack_order_not_insertion_order(self):
        # Written exfiltration-first on purpose.
        self._finding('EXFIL_VOLUME_ASYMMETRY', flow=self._flow(40))
        self._finding('RECON_PORT_SCAN', flow=self._flow(0),
                      evidence={'source_is_internal': False})
        self._finding('C2_BEACON_PERIODIC', flow=self._flow(20))

        host = reconstruct(self.session)['hosts'][0]
        self.assertEqual(
            [s['tactic'] for s in host['stages']],
            ['Reconnaissance', 'Command and Control', 'Exfiltration'],
        )
        self.assertEqual([s['order'] for s in host['stages']], [1, 12, 13])

    def test_order_uses_packet_time_and_not_the_analysis_clock(self):
        """
        Every finding in a capture is written within the same second, so
        `created_at` cannot order anything. The stage windows have to come from
        the flows.
        """
        self._finding('C2_BEACON_PERIODIC', flow=self._flow(20))
        self._finding('EXFIL_VOLUME_ASYMMETRY', flow=self._flow(40))

        stages = reconstruct(self.session)['hosts'][0]['stages']
        self.assertEqual(stages[0]['first_seen'],
                         (T0 + timedelta(minutes=20)).isoformat())
        self.assertEqual(stages[1]['first_seen'],
                         (T0 + timedelta(minutes=40)).isoformat())

    def test_a_finding_with_no_flow_carries_no_invented_timestamp(self):
        self._finding('C2_BEACON_PERIODIC')
        stage = reconstruct(self.session)['hosts'][0]['stages'][0]
        self.assertIsNone(stage['first_seen'])
        self.assertIsNone(stage['findings'][0]['first_seen'])

    # ── the refusals ────────────────────────────────────────────────────────

    def test_the_packet_clock_contradicting_attack_order_is_reported(self):
        """
        Exfiltration timestamped before the C2 channel that supposedly carried
        it. The stages still print in ATT&CK order — that is the convention —
        but the disagreement is stated rather than smoothed away.
        """
        self._finding('EXFIL_VOLUME_ASYMMETRY', flow=self._flow(5))
        self._finding('C2_BEACON_PERIODIC', flow=self._flow(30))

        host = reconstruct(self.session)['hosts'][0]
        self.assertEqual([s['tactic'] for s in host['stages']],
                         ['Command and Control', 'Exfiltration'])
        self.assertEqual(len(host['time_conflicts']), 1)
        conflict = host['time_conflicts'][0]
        self.assertEqual(conflict['expected_first'], 'Command and Control')
        self.assertEqual(conflict['observed_first'], 'Exfiltration')
        self.assertIn('do not follow that order', host['summary'])

    def test_unmappable_findings_are_kept_with_their_reason(self):
        """
        Two rules map to no technique by design. Dropping them would lose a
        corroboration finding — the one that says several rules agree about
        this machine — from the only view that assembles a host's story.
        """
        self._finding('C2_BEACON_PERIODIC', flow=self._flow(10))
        self._finding('HOST_CORROBORATED', severity='critical')
        self._finding('ANOMALY_STATISTICAL', severity='medium')

        host = reconstruct(self.session)['hosts'][0]
        self.assertEqual(host['finding_count'], 3)
        self.assertEqual(len(host['stages']), 1)
        rules = {row['rule_id'] for row in host['unclassified']}
        self.assertEqual(rules, {'HOST_CORROBORATED', 'ANOMALY_STATISTICAL'})
        for row in host['unclassified']:
            self.assertTrue(row['why_no_technique'])
        self.assertIn('support the picture', host['summary'])

    def test_an_unknown_rule_is_not_given_a_plausible_technique(self):
        self._finding('SOME_RULE_ADDED_LATER', flow=self._flow(1))
        host = reconstruct(self.session)['hosts'][0]
        self.assertEqual(host['stages'], [])
        self.assertEqual(len(host['unclassified']), 1)

    def test_the_tactics_traffic_cannot_evidence_are_always_named(self):
        """
        A reconstruction showing four filled stages and nothing else tells the
        reader an attack had four steps. It did not — the tool was watching the
        wire, not the endpoint.
        """
        self._finding('C2_BEACON_PERIODIC', flow=self._flow(10))
        result = reconstruct(self.session)

        self.assertEqual(len(result['unobservable']), 10)
        self.assertEqual(result['tactics_total'], 14)
        self.assertEqual(len(TACTIC_ORDER), 14)

        named = {row['tactic'] for row in result['unobservable']}
        self.assertIn('Initial Access', named)
        self.assertIn('Lateral Movement', named)
        for row in result['unobservable']:
            self.assertTrue(row['reason'])
            self.assertIn(row['tactic_id'], TACTIC_ORDER)

        # No tactic is claimed both observable and unobservable.
        observed = {s['tactic_id'] for h in result['hosts'] for s in h['stages']}
        self.assertFalse(observed & {row['tactic_id'] for row in result['unobservable']})

    def test_it_never_states_the_sequence_as_causation(self):
        self._finding('C2_BEACON_PERIODIC', flow=self._flow(10))
        self._finding('EXFIL_VOLUME_ASYMMETRY', flow=self._flow(30))
        result = reconstruct(self.session)

        self.assertIn('not a finding', result['basis'])
        self.assertIn('has not been cleared', result['limits'])
        # "was seen at", never "then exfiltrated" or "used the channel to".
        self.assertIn('was seen at', result['hosts'][0]['summary'])

    # ── determinism ─────────────────────────────────────────────────────────

    def test_the_same_capture_reconstructs_identically(self):
        """
        An examiner has to be able to put this in a report and have it hold.
        """
        self._finding('C2_BEACON_PERIODIC', flow=self._flow(10))
        self._finding('EXFIL_VOLUME_ASYMMETRY', flow=self._flow(30))
        self._finding('RECON_PORT_SCAN', flow=self._flow(1),
                      evidence={'source_is_internal': True})
        self._finding('HOST_CORROBORATED', severity='critical')
        self._finding('C2_BEACON_PERIODIC', subject='10.0.0.9',
                      flow=self._flow(15, src='10.0.0.9'))

        self.assertEqual(reconstruct(self.session), reconstruct(self.session))

    def test_hosts_are_ranked_worst_first(self):
        self._finding('C2_BEACON_PERIODIC', severity='medium',
                      subject='10.0.0.5', flow=self._flow(10))
        self._finding('EXFIL_VOLUME_ASYMMETRY', severity='critical',
                      subject='10.0.0.9', flow=self._flow(12, src='10.0.0.9'))

        hosts = [h['host'] for h in reconstruct(self.session)['hosts']]
        self.assertEqual(hosts, ['10.0.0.9', '10.0.0.5'])

    def test_min_findings_raises_the_bar_for_appearing(self):
        self._finding('C2_BEACON_PERIODIC', subject='10.0.0.5', flow=self._flow(10))
        self._finding('EXFIL_VOLUME_ASYMMETRY', subject='10.0.0.5', flow=self._flow(20))
        self._finding('C2_BEACON_PERIODIC', subject='10.0.0.9',
                      flow=self._flow(11, src='10.0.0.9'))

        self.assertEqual(len(reconstruct(self.session, min_findings=1)['hosts']), 2)
        self.assertEqual(len(reconstruct(self.session, min_findings=2)['hosts']), 1)

    # ── the port-scan branch, which is genuinely bimodal ─────────────────────

    def test_an_inside_scan_is_discovery_and_an_outside_scan_is_reconnaissance(self):
        self._finding('RECON_PORT_SCAN', subject='10.0.0.5', flow=self._flow(1),
                      evidence={'source_is_internal': True})
        self._finding('RECON_PORT_SCAN', subject='203.0.113.9',
                      flow=self._flow(2, src='203.0.113.9'),
                      evidence={'source_is_internal': False})

        by_host = {h['host']: h for h in reconstruct(self.session)['hosts']}
        self.assertEqual(by_host['10.0.0.5']['stages'][0]['tactic'], 'Discovery')
        self.assertEqual(by_host['203.0.113.9']['stages'][0]['tactic'],
                         'Reconnaissance')
