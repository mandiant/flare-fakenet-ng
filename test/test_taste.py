# Copyright 2025 Google LLC

"""Unit tests for the listeners' taste() protocol detection callbacks.

These do not need administrator rights or a running FakeNet, unlike test.py.
"""

import logging
import os
import sys
import unittest

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fakenet.listeners import TFTPListener


class TestTFTPTaste(unittest.TestCase):

    def setUp(self):
        self.listener = TFTPListener.TFTPListener(
            {
                'ipaddr': '192.0.2.1',
                'port': '69',
                'protocol': 'UDP',
                'tftproot': 'defaultFiles',
                'tftpfileprefix': 'tftp',
            },
            logging_level=logging.CRITICAL,
        )

    def test_taste_recognises_every_opcode(self):
        """Every well formed TFTP packet on port 69 must score above the
        RawListener's flat confidence of 1, otherwise the proxy hands TFTP
        traffic to the wrong listener."""
        packets = (
            ('RRQ', TFTPListener.OPCODE_RRQ + b'file.txt\x00netascii\x00'),
            ('WRQ', TFTPListener.OPCODE_WRQ + b'file.txt\x00netascii\x00'),
            ('DATA', TFTPListener.OPCODE_DATA + b'\x00\x01' + b'A' * 16),
            ('ACK', TFTPListener.OPCODE_ACK + b'\x00\x01'),
            ('ERROR', TFTPListener.OPCODE_ERROR + b'\x00\x01msg\x00'),
        )
        for name, data in packets:
            with self.subTest(opcode=name):
                self.assertEqual(self.listener.taste(data, 69), 3)

    def test_taste_ignores_other_protocols(self):
        """Traffic that is not TFTP must still return a confidence rather
        than raising, so that the caller's scoring loop is not skipped."""
        self.assertEqual(
            self.listener.taste(b'GET / HTTP/1.1\r\n\r\n', 80), 0)


if __name__ == '__main__':
    unittest.main()
