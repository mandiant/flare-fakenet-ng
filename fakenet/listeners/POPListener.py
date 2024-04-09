# Copyright (C) 2016-2023 Mandiant, Inc. All rights reserved.

import logging

import sys
import os

import threading
import socketserver

import ssl
import socket

from . import *

EMAIL = b"""From: "Bob Example" <bob@example.org>
To: Alice Example <alice@example.com>
Cc: theboss@example.com
Date: Tue, 15 January 2008 16:02:43 -0500
Subject: Test message

Hello Alice.
This is a test message with 5 header fields and 4 lines in the message body.
Your friend,
Bob\r\n"""

class POPListener(object):

    # Once the TCP connection has been established, the POP server initiates 
    # the conversation with +OK message. However, if the client connects
    # to a port that is not 110, there is no way for the proxy to know that
    # POP is the protocol until the client sends a message.
    def taste(self, data, dport):

        commands = [ b'QUIT', b'STAT', b'LIST', b'RETR', b'DELE', b'NOOP', b'RSET',
                b'TOP', b'UIDL', b'USER', b'PASS', b'APOP' ]

        confidence = 1 if dport == 110 else 0

        data = data.lstrip()
        for command in commands:
            if data.startswith(command):
                confidence += 2

        return confidence

    def __init__(self, 
            config, 
            name='POPListener', 
            logging_level=logging.INFO, 
            ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)

        self.config = config
        self.name = name
        self.local_ip = config.get('ipaddr')
        self.server = None
        self.name = 'POP'
        self.port = self.config.get('port', 110)

        self.logger.debug('Starting...')

        self.logger.debug('Initialized with config:')
        for key, value in config.items():
            self.logger.debug('  %10s: %s', key, value)

    def start(self):
        self.logger.debug('Starting...')
        
        self.server = ThreadedTCPServer((self.local_ip, int(self.config['port'])), ThreadedTCPRequestHandler)

        if self.config.get('usessl') == 'Yes':
            self.logger.debug('Using SSL socket')

            keyfile_path = 'listeners/ssl_utils/privkey.pem'
            keyfile_path = ListenerBase.abs_config_path(keyfile_path)
            if keyfile_path is None:
                self.logger.error('Could not locate %s', keyfile_path)
                sys.exit(1)

            certfile_path = 'listeners/ssl_utils/server.pem'
            certfile_path = ListenerBase.abs_config_path(certfile_path)
            if certfile_path is None:
                self.logger.error('Could not locate %s', certfile_path)
                sys.exit(1)

            self.server.socket = ssl.wrap_socket(self.server.socket, keyfile='privkey.pem', certfile='server.pem', server_side=True, ciphers='RSA')

        self.server.logger = self.logger
        self.server.config = self.config

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.debug('Stopping...')
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def acceptDiverterListenerCallbacks(self, diverterListenerCallbacks):
        self.server.diverterListenerCallbacks = diverterListenerCallbacks

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):

        # Timeout connection to prevent hanging
        self.request.settimeout(int(self.server.config.get('timeout', 10)))

        try:

            self.request.sendall(b"+OK FakeNet POP3 Server Ready\r\n")
            while True:

                data = self.request.recv(1024)

                if not data:
                    break

                elif len(data) > 0:

                    for line in data.split(b"\r\n"):

                        if line and len(line) > 0:

                            if b' ' in line:
                                cmd, params = line.split(b' ', 1)
                            else:
                                cmd, params = line, b''

                            cmd = cmd.decode("utf-8").upper()
                            handler = getattr(self, 'pop_%s' % (cmd), self.pop_DEFAULT)
                            handler(cmd, params)
                            # Collect NBIs
                            nbi = {
                                'Command': cmd,
                                'Params': params
                                }
                            self.collect_nbi(nbi)

        except socket.timeout:
            self.server.logger.warning('Connection timeout')

        except socket.error as msg:
            self.server.logger.error('Socket Error: %s', msg.strerror or msg)

        except Exception as e:
            self.server.logger.error('Error: %s', e)

    def pop_DEFAULT(self, cmd, params):
        self.server.logger.info('Client issued an unknown command %s %s', cmd, params)
        self.request.sendall(b"-ERR Unknown command\r\n")

    def pop_APOP(self, cmd, params):

        if b' ' in params:
            mailbox_name, digest = params.split(b' ', 1)
            self.server.logger.info('Client requests access to mailbox %s', mailbox_name)

            self.request.sendall(b"+OK %s's maildrop has 2 messages (320 octets)\r\n" % mailbox_name)

        else:
            self.server.logger.info('Client sent invalid APOP command: APOP %s', params)
            self.request.sendall(b"-ERR\r\n")

    def pop_RPOP(self, cmd, params):

        mailbox_name = params
        self.server.logger.info('Client requests access to mailbox %s', mailbox_name)

        self.request.sendall(b"+OK %s's maildrop has 2 messages (320 octets)\r\n" % mailbox_name)

    def pop_USER(self, cmd, params):

        self.server.logger.info('Client user: %s', params)

        self.request.sendall(b"+OK User accepted\r\n")

    def pop_PASS(self, cmd, params):

        self.server.logger.info('Client password: %s', params)

        self.request.sendall(b"+OK Pass accepted\r\n")

    def pop_STAT(self, cmd, params):

        self.request.sendall(b"+OK 2 320\r\n")

    def pop_LIST(self, cmd, params):

        # List all messages
        if params == b'':

            self.request.sendall(b"+OK 2 messages (320 octets)\r\n")
            self.request.sendall(b"1 120\r\n")
            self.request.sendall(b"2 200\r\n")
            self.request.sendall(b".\r\n")

        # List individual message
        else:
            self.request.sendall(b"+OK %d 200\r\n" % params)
            self.request.sendall(b".\r\n")


    def pop_RETR(self, cmd, params):

        self.server.logger.info('Client requests message %s', params)

        self.request.sendall(b"+OK 120 octets\r\n")
        self.request.sendall(EMAIL + b"\r\n")
        self.request.sendall(b".\r\n")

    def pop_DELE(self, cmd, params):

        self.server.logger.info('Client requests message %s to be deleted', params)

        self.request.sendall(b"+OK message %s deleted\r\n", params)

    def pop_NOOP(self, cmd, params):
        self.request.sendall(b"+OK\r\n")

    def pop_RSET(self, cmd, params):
        self.request.sendall(b"+OK maildrop has 2 messages (320 octets)\r\n")

    def pop_TOP(self, cmd, params):
        self.request.sendall(b"+OK\r\n")
        self.request.sendall(b"1 120\r\n")
        self.request.sendall(b"2 200\r\n")
        self.request.sendall(b".\r\n")

    def pop_UIDL(self, cmd, params):

        if params == b'':
            self.request.sendall(b"+OK\r\n")
            self.request.sendall(b"1 whqtswO00WBw418f9t5JxYwZa\r\n")
            self.request.sendall(b"2 QhdPYR:00WBw1Ph7x7a\r\n")
            self.request.sendall(b".\r\n")

        else:
            self.request.sendall(b"+OK %s QhdPYR:00WBw1Ph7x7\r\n", params)

    def pop_QUIT(self, cmd, params):

        self.request.sendall(b"+OK FakeNet POP3 server signing off\r\n")

    def collect_nbi(self, nbi):
        # Report diverter everytime we capture an NBI.
        self.server.diverterListenerCallbacks.logNbi(self.client_address[1],
                nbi, 'TCP', 'POP', self.server.config.get('usessl'))


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

###############################################################################
# Testing code
def test(config):

    import poplib

    logger = logging.getLogger('POPListenerTest')

    server = poplib.POP3_SSL('localhost', config.get('port', 110))

    logger.info('Authenticating.')
    server.user('username')
    server.pass_('password')

    logger.info('Listing and retrieving messages.')
    print(server.list())
    print(server.retr(1))
    server.quit()

def main():
    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)

    config = {'port': '110', 'usessl': 'Yes', 'timeout': 30 }

    listener = POPListener(config)
    listener.start()

    ###########################################################################
    # Run processing
    import time

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    ###########################################################################
    # Run tests
    test(config)

if __name__ == '__main__':
    main()
