"""
Tests for the clock attestation.

The module's whole purpose is to be candid when it does not know something, so
most of these tests are about what it does when the machine will not answer.
"""

from unittest.mock import patch

from django.test import SimpleTestCase

from . import timesource


class TimeSourceTests(SimpleTestCase):
    def test_reports_synchronised_when_systemd_says_so(self):
        with patch.object(timesource, '_read_timedatectl', return_value={
            'NTPSynchronized': 'yes', 'Timezone': 'Asia/Kolkata', 'LocalRTC': 'no',
        }):
            state = timesource.describe()
        self.assertEqual(state['synchronisation'], timesource.SYNCHRONISED)
        self.assertEqual(state['timezone'], 'Asia/Kolkata')
        self.assertFalse(state['rtc_in_local_time'])

    def test_reports_unsynchronised_on_an_air_gapped_machine(self):
        """The expected state of the machine this platform is built for."""
        with patch.object(timesource, '_read_timedatectl', return_value={
            'NTPSynchronized': 'no', 'Timezone': 'Asia/Kolkata', 'LocalRTC': 'no',
        }):
            state = timesource.describe()
        self.assertEqual(state['synchronisation'], timesource.UNSYNCHRONISED)
        # The note has to say what it means for the reader, not just name the
        # state — this text is printed on a court exhibit.
        self.assertIn('drifts', state['note'])
        self.assertIn('air-gapped', timesource.summary_line(state))

    def test_unknown_when_the_machine_will_not_say(self):
        with patch.object(timesource, '_read_timedatectl', return_value=None):
            state = timesource.describe()
        self.assertEqual(state['synchronisation'], timesource.UNKNOWN)
        self.assertEqual(state['source'], 'unavailable')

    def test_an_unrecognised_value_is_unknown_not_a_guess(self):
        """
        If systemd renames the field or reports something new, the honest
        answer is 'unknown'. Defaulting to 'synchronised' would overclaim and
        defaulting to 'unsynchronised' would understate — both are inventions.
        """
        for raw in ('', 'maybe', 'n/a'):
            with self.subTest(raw=raw):
                with patch.object(timesource, '_read_timedatectl',
                                  return_value={'NTPSynchronized': raw}):
                    self.assertEqual(
                        timesource.describe()['synchronisation'],
                        timesource.UNKNOWN,
                    )

    def test_local_rtc_is_reported(self):
        with patch.object(timesource, '_read_timedatectl', return_value={
            'NTPSynchronized': 'no', 'LocalRTC': 'yes',
        }):
            self.assertTrue(timesource.describe()['rtc_in_local_time'])

    def test_never_raises_when_the_binary_misbehaves(self):
        """
        A module that exists to report uncertainty must not itself throw. Every
        failure of the underlying command resolves to UNKNOWN.
        """
        import subprocess

        for boom in (OSError('nope'), subprocess.TimeoutExpired('timedatectl', 5)):
            with self.subTest(boom=type(boom).__name__):
                with patch('shutil.which', return_value='/usr/bin/timedatectl'), \
                     patch('subprocess.run', side_effect=boom):
                    self.assertEqual(
                        timesource.describe()['synchronisation'],
                        timesource.UNKNOWN,
                    )

    def test_missing_binary_is_handled(self):
        with patch('shutil.which', return_value=None):
            self.assertIsNone(timesource._read_timedatectl())

    def test_every_state_has_a_note_and_a_summary(self):
        for state in (timesource.SYNCHRONISED, timesource.UNSYNCHRONISED,
                      timesource.UNKNOWN):
            with self.subTest(state=state):
                self.assertIn(state, timesource.NOTES)
                self.assertTrue(timesource.NOTES[state].strip())
                line = timesource.summary_line(
                    {'synchronisation': state, 'timezone': 'Asia/Kolkata'})
                self.assertIn('Asia/Kolkata', line)

    def test_it_makes_no_network_call(self):
        """
        The point of this module is to describe an offline machine. If it ever
        reached for a time server it would hang for the timeout on exactly the
        machine it was written for.
        """
        import socket

        with patch.object(socket.socket, 'connect',
                          side_effect=AssertionError('opened a socket')):
            timesource.describe()
