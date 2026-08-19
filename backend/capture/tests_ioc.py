"""
Tests over threat-intelligence feeds.

A feed match is the one place this engine reports somebody else's evidence, and
almost everything that can go wrong with it is a way of accusing the wrong
machine or overstating what a list actually establishes. So the tests here are
mostly about restraint: that a listed domain does not match a lookalike, that
the host inside the network is never the one accused, that a feed compiled long
after the traffic says so, and that a list nobody carried to this machine
produces silence rather than an error.
"""

import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from django.test import TestCase

from .detection import RULE_IDS, rule_ioc_feed_match
from .ioc import import_feed, match_session, parse
from .models import CaptureSession, DNSRecord, Detection, Flow, IOCFeed, IOCIndicator

T0 = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def write(text):
    path = Path(tempfile.mkdtemp()) / 'feed.csv'
    path.write_text(text, encoding='utf-8')
    return path


FEODO = """# Feodo Tracker fixture
# Last updated: 2026-04-01 00:00:00 UTC
# first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
2026-03-01 08:00:00,203.0.113.50,443,online,2026-03-30,Fixturebot
2026-03-02 09:00:00,198.51.100.60,8080,online,2026-03-30,Fixturebot
"""


class FeedParsingTests(TestCase):
    def test_the_feeds_own_generation_time_is_read_not_the_import_time(self):
        _, published = parse(FEODO, IOCFeed.Format.FEODO_IP)
        self.assertEqual(published, datetime(2026, 4, 1, tzinfo=timezone.utc))

    def test_a_file_without_a_generation_line_leaves_it_null(self):
        _, published = parse('203.0.113.50\n', IOCFeed.Format.PLAIN_IP)
        self.assertIsNone(published)

    def test_malformed_rows_are_skipped_rather_than_guessed_at(self):
        text = FEODO + 'this,is,not,an,address,at,all\n,,,\n'
        rows, _ = parse(text, IOCFeed.Format.FEODO_IP)
        self.assertEqual({r['value'] for r in rows},
                         {'203.0.113.50', '198.51.100.60'})

    def test_the_row_is_kept_verbatim_so_a_finding_can_quote_it(self):
        rows, _ = parse(FEODO, IOCFeed.Format.FEODO_IP)
        first = next(r for r in rows if r['value'] == '203.0.113.50')
        self.assertIn('Fixturebot', first['source_line'])
        self.assertIn('Fixturebot', first['context'])
        self.assertIn('port 443', first['context'])

    def test_urlhaus_indexes_the_host_as_well_as_the_url(self):
        text = (
            '# Last updated: 2026-04-01 00:00:00 UTC\n'
            '"1","2026-03-04 10:00:00","http://bad.example/payload.bin",'
            '"online","2026-03-30","malware_download","tag","link","reporter"\n'
        )
        rows, _ = parse(text, IOCFeed.Format.URLHAUS)
        kinds = {(r['kind'], r['value']) for r in rows}
        self.assertIn((IOCIndicator.Kind.URL, 'http://bad.example/payload.bin'), kinds)
        # A capture sees the name resolved and the connection made, essentially
        # never the path — so the host has to be indexed too or the feed would
        # match nothing this tool can observe.
        self.assertIn((IOCIndicator.Kind.DOMAIN, 'bad.example'), kinds)

    def test_a_file_that_parses_to_nothing_is_refused(self):
        """
        A feed row that exists and matches nothing looks exactly like a feed
        that is working and finding nothing.
        """
        path = write('# only comments\n\n')
        with self.assertRaises(ValueError) as caught:
            import_feed(path, name='empty', fmt=IOCFeed.Format.FEODO_IP,
                        retrieved_on=date(2026, 4, 2))
        self.assertIn('zero indicators', str(caught.exception))
        self.assertFalse(IOCFeed.objects.exists())

    def test_the_file_digest_is_recorded(self):
        path = write(FEODO)
        feed = import_feed(path, name='fixture', fmt=IOCFeed.Format.FEODO_IP,
                           retrieved_on=date(2026, 4, 2), source='local fixture')
        self.assertEqual(len(feed.file_sha256), 64)
        self.assertEqual(feed.entry_count, 2)
        self.assertEqual(feed.retrieved_on, date(2026, 4, 2))


class FeedMatchingTests(TestCase):
    def setUp(self):
        self.session = CaptureSession.objects.create(
            name='ioc-fixture', source_type='pcap', state='completed',
            home_net='10.0.0.0/24',
        )

    def _feed(self, text=FEODO, fmt=IOCFeed.Format.FEODO_IP,
              retrieved=date(2026, 4, 2)):
        return import_feed(write(text), name='fixture feed', fmt=fmt,
                           retrieved_on=retrieved, source='fixture')

    def _flow(self, dst, src='10.0.0.5', sni='', host='', at=T0):
        return Flow.objects.create(
            session=self.session, src_ip=src, dst_ip=dst,
            src_port=51000, dst_port=443, protocol='TCP',
            initiator_ip=src, initiator_confirmed=True,
            tls_sni=sni, http_host=host,
            first_seen=at, last_seen=at + timedelta(seconds=5),
        )

    # ── who gets accused ────────────────────────────────────────────────────

    def test_the_host_inside_the_network_is_the_subject_not_the_match(self):
        self._feed()
        self._flow('203.0.113.50')
        hit = match_session(self.session)[0]
        self.assertEqual(hit['subject_ip'], '10.0.0.5')
        self.assertEqual(hit['observed'], '203.0.113.50')

    def test_an_internal_address_is_never_matched_against_a_blocklist(self):
        """
        Matching the inside end would fire on the victim. Both ends of this
        flow are listed; only the external one may produce a finding.
        """
        self._feed('10.0.0.5\n203.0.113.50\n', IOCFeed.Format.PLAIN_IP)
        self._flow('203.0.113.50')
        observed = {h['observed'] for h in match_session(self.session)}
        self.assertEqual(observed, {'203.0.113.50'})

    # ── name matching ───────────────────────────────────────────────────────

    def test_a_listed_domain_matches_its_subdomains(self):
        self._feed('evil.example\n', IOCFeed.Format.PLAIN_DOMAIN)
        self._flow('203.0.113.9', sni='c2.evil.example')
        hits = match_session(self.session)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['where'], 'TLS server name')

    def test_a_listed_domain_does_not_match_a_lookalike(self):
        """
        The failure a substring test would produce: `evil.example` matching
        `notevil.example`, which is a different registration owned by somebody
        else. The check has to walk label boundaries.
        """
        self._feed('evil.example\n', IOCFeed.Format.PLAIN_DOMAIN)
        self._flow('203.0.113.9', sni='notevil.example')
        self._flow('203.0.113.9', host='evil.example.co')
        self.assertEqual(match_session(self.session), [])

    def test_a_dns_query_for_a_listed_name_is_matched(self):
        self._feed('evil.example\n', IOCFeed.Format.PLAIN_DOMAIN)
        DNSRecord.objects.create(
            session=self.session, src_ip='10.0.0.7',
            query_name='data.evil.example.', query_type='A', timestamp=T0,
        )
        hit = match_session(self.session)[0]
        self.assertEqual(hit['where'], 'DNS query')
        self.assertEqual(hit['subject_ip'], '10.0.0.7')
        self.assertEqual(hit['observed'], 'data.evil.example')

    # ── dating the claim ────────────────────────────────────────────────────

    def test_a_feed_compiled_before_the_traffic_reports_a_negative_gap(self):
        self._feed()  # published 2026-04-01; traffic at 2026-05-01
        self._flow('203.0.113.50')

        hit = match_session(self.session)[0]
        self.assertLess(hit['staleness_days'], 0)

        finding = rule_ioc_feed_match(self.session)[0]
        self.assertEqual(finding.severity, Detection.Severity.HIGH)
        self.assertIn('before the traffic was recorded', finding.rationale)

    def test_a_feed_compiled_long_after_the_traffic_steps_the_severity_down(self):
        """
        Addresses are reassigned. A list built a year later may be describing
        somebody else's use of the address, and the finding has to say so
        rather than presenting both cases as "known malicious".
        """
        late = FEODO.replace('2026-04-01 00:00:00 UTC', '2027-04-01 00:00:00 UTC')
        self._feed(late, retrieved=date(2027, 4, 2))
        self._flow('203.0.113.50')

        hit = match_session(self.session)[0]
        self.assertGreater(hit['staleness_days'], 90)

        finding = rule_ioc_feed_match(self.session)[0]
        self.assertEqual(finding.severity, Detection.Severity.MEDIUM)
        self.assertIn('reassigned', finding.rationale)

    def test_a_feed_match_never_reaches_critical(self):
        self._feed()
        self._flow('203.0.113.50')
        for finding in rule_ioc_feed_match(self.session):
            self.assertNotEqual(finding.severity, Detection.Severity.CRITICAL)
            self.assertIn('Capped at HIGH', finding.evidence['severity_cap'])

    # ── what the finding carries ────────────────────────────────────────────

    def test_the_finding_quotes_the_line_and_the_files_digest(self):
        feed = self._feed()
        self._flow('203.0.113.50')
        evidence = rule_ioc_feed_match(self.session)[0].evidence

        self.assertEqual(evidence['feed_file_sha256'], feed.file_sha256)
        self.assertIn('Fixturebot', evidence['feed_line'])
        self.assertEqual(evidence['feed_retrieved_on'], '2026-04-02')
        self.assertIn('third-party assertion', evidence['evidence_class'])

    def test_many_conversations_with_one_address_make_one_finding(self):
        """
        A beacon calling every forty-five seconds produces hundreds of flows
        asserting one thing. Emitted per flow they would bury the queue and the
        triage backlog would measure how chatty the malware was.
        """
        self._feed()
        for i in range(25):
            self._flow('203.0.113.50', at=T0 + timedelta(minutes=i))

        findings = rule_ioc_feed_match(self.session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence['conversations_matching'], 25)
        # The exemplar is the earliest, so the timestamp is when it started.
        self.assertEqual(findings[0].evidence['earliest_seen'], T0.isoformat())

    # ── the quiet case ──────────────────────────────────────────────────────

    def test_no_feed_loaded_produces_silence_and_not_an_error(self):
        """
        The normal state of an air-gapped workstation nobody has carried a feed
        to. Silence is the correct behaviour, not a misconfiguration.
        """
        self._flow('203.0.113.50')
        self.assertEqual(match_session(self.session), [])
        self.assertEqual(rule_ioc_feed_match(self.session), [])

    def test_a_loaded_feed_that_matches_nothing_produces_silence_too(self):
        self._feed()
        self._flow('192.0.2.200')
        self.assertEqual(rule_ioc_feed_match(self.session), [])

    def test_the_rule_is_in_the_published_inventory(self):
        self.assertIn('IOC_FEED_MATCH', RULE_IDS)

    def test_the_rule_carries_no_attack_technique_and_says_why(self):
        from .attack_mapping import classify, describe

        self._feed()
        self._flow('203.0.113.50')
        finding = rule_ioc_feed_match(self.session)[0]
        finding.save()

        self.assertEqual(classify(finding), [])
        self.assertIn('not about a technique', describe(finding))
