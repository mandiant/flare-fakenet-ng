import logging

import sys
import os

import threading
import SocketServer

import ssl
import socket

from . import *

EMAIL = """From: "Bob Example" <bob@example.org>
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

        commands = [ 'QUIT', 'STAT', 'LIST', 'RETR', 'DELE', 'NOOP', 'RSET', 
                'TOP', 'UIDL', 'USER', 'PASS', 'APOP' ]

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
        for key, value in config.iteritems():
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

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):

        # Timeout connection to prevent hanging
        self.request.settimeout(int(self.server.config.get('timeout', 10)))

        try:

            self.request.sendall("+OK FakeNet POP3 Server Ready\r\n")
            while True:

                data = self.request.recv(1024)

                if not data:
                    break

                elif len(data) > 0:

                    for line in data.split("\r\n"):

                        if line and len(line) > 0:

                            if ' ' in line:
                                cmd, params = line.split(' ', 1)
                            else:
                                cmd, params = line, ''

                            handler = getattr(self, 'pop_%s' % (cmd.upper()), self.pop_DEFAULT)
                            handler(cmd, params)

        except socket.timeout:
            self.server.logger.warning('Connection timeout')

        except socket.error as msg:
            self.server.logger.error('Error: %s', msg.strerror or msg)

        except Exception, e:
            self.server.logger.error('Error: %s', e)

    def pop_DEFAULT(self, cmd, params):
        self.server.logger.info('Client issued an unknown command %s %s', cmd, params)
        self.request.sendall("-ERR Unknown command\r\n")

    def pop_APOP(self, cmd, params):

        if ' ' in params:
            mailbox_name, digest = params.split(' ', 1)
            self.server.logger.info('Client requests access to mailbox %s', mailbox_name)

            self.request.sendall("+OK %s's maildrop has 2 messages (320 octets)\r\n" % mailbox_name)

        else:
            self.server.logger.info('Client sent invalid APOP command: APOP %s', params)
            self.request.sendall("-ERR\r\n")

    def pop_RPOP(self, cmd, params):

        mailbox_name = params
        self.server.logger.info('Client requests access to mailbox %s', mailbox_name)

        self.request.sendall("+OK %s's maildrop has 2 messages (320 octets)\r\n" % mailbox_name)

    def pop_USER(self, cmd, params):

        self.server.logger.info('Client user: %s', params)

        self.request.sendall("+OK User accepted\r\n")

    def pop_PASS(self, cmd, params):

        self.server.logger.info('Client password: %s', params)

        self.request.sendall("+OK Pass accepted\r\n")

    def pop_STAT(self, cmd, params):

        self.request.sendall("+OK 2 320\r\n")

    def pop_LIST(self, cmd, params):

        # List all messages
        if params == '':

            self.request.sendall("+OK 2 messages (320 octets)\r\n")
            self.request.sendall("1 120\r\n")
            self.request.sendall("2 200\r\n")
            self.request.sendall(".\r\n")

        # List individual message
        else:
            self.request.sendall("+OK %d 200\r\n" % params)
            self.request.sendall(".\r\n")


    def pop_RETR(self, cmd, params):

        self.server.logger.info('Client requests message %s', params)

        self.request.sendall("+OK 120 octets\r\n")
        self.request.sendall(EMAIL + "\r\n")
        self.request.sendall(".\r\n")

    def pop_DELE(self, cmd, params):

        self.server.logger.info('Client requests message %s to be deleted', params)

        self.request.sendall("+OK message %s deleted\r\n", params)

    def pop_NOOP(self, cmd, params):
        self.request.sendall("+OK\r\n")

    def pop_RSET(self, cmd, params):
        self.request.sendall("+OK maildrop has 2 messages (320 octets)\r\n")

    def pop_TOP(self, cmd, params):
        self.request.sendall("+OK\r\n")
        self.request.sendall("1 120\r\n")
        self.request.sendall("2 200\r\n")
        self.request.sendall(".\r\n")

    def pop_UIDL(self, cmd, params):

        if params == '':
            self.request.sendall("+OK\r\n")
            self.request.sendall("1 whqtswO00WBw418f9t5JxYwZa\r\n")
            self.request.sendall("2 QhdPYR:00WBw1Ph7x7a\r\n")
            self.request.sendall(".\r\n")

        else:
            self.request.sendall("+OK %s QhdPYR:00WBw1Ph7x7\r\n", params)

    def pop_QUIT(self, cmd, params):

        self.request.sendall("+OK FakeNet POP3 server signing off\r\n")


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
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
    print server.list()
    print server.retr(1)
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
