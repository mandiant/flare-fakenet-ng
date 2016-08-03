import logging

import sys
import os

import threading
import SocketServer

import ssl
import socket

class SMTPListener():

    def __init__(self, config, name = 'SMTPListener', logging_level = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)

        self.config = config
        self.name = name
        self.local_ip = '0.0.0.0'
        self.server = None

        self.logger.info('Starting...')

        self.logger.debug('Initialized with config:')
        for key, value in config.iteritems():
            self.logger.debug('  %10s: %s', key, value)

    def start(self):
        self.logger.debug('Starting...')

        self.server = ThreadedTCPServer((self.local_ip, int(self.config['port'])), ThreadedTCPRequestHandler)

        if self.config.get('usessl') == 'Yes':
            self.logger.debug('Using SSL socket')

            keyfile_path = 'privkey.pem'
            if not os.path.exists(keyfile_path):
                keyfile_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), keyfile_path)

                if not os.path.exists(keyfile_path):
                    self.logger.error('Could not locate privkey.pem')
                    sys.exit(1)

            certfile_path = 'server.pem'
            if not os.path.exists(certfile_path):
                certfile_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), certfile_path)

                if not os.path.exists(certfile_path):
                    self.logger.error('Could not locate certfile.pem')
                    sys.exit(1)

            self.server.socket = ssl.wrap_socket(self.server.socket, keyfile='privkey.pem', certfile='server.pem', server_side=True, ciphers='RSA')

        self.server.logger = self.logger
        self.server.config = self.config

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.info('Stopping...')
        if self.server:
            self.server.shutdown()
            self.server.server_close()

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):

        # Timeout connection to prevent hanging
        self.request.settimeout(int(self.server.config.get('timeout', 5)))

        try:

            self.request.sendall("220 PracticalMalwareAnalysis.COM STMP Service Ready\r\n")
            while True:
                data = self.request.recv(4096)
                self.server.logger.info('Recieved Data.')
                for line in data.split("\n"):
                    self.server.logger.debug(line)

                command = data[:4].upper()

                if command == '':
                    break

                elif command == 'HELO':
                    self.request.sendall("250 PracticalMalwareAnalysis.com\r\n")

                elif command in ['MAIL', 'RCPT', 'NOOP', 'RSET']:
                    self.request.sendall("250 OK\r\n")

                elif command == 'QUIT':
                    self.request.sendall("221 PracticalMalwareAnalysis.com bye\r\n")

                elif command == "DATA":
                    self.request.sendall("354 start mail input, end with <CRLF>.<CRLF>\r\n")

                    mail_data = ""
                    while True:
                        mail_data_chunk = self.request.recv(4096)

                        if not mail_data_chunk:
                            break

                        mail_data += mail_data_chunk

                        if "\r\n.\r\n" in mail_data:
                            break

                    self.server.logger.info('Received mail data.')
                    for line in mail_data.split("\n"):
                        self.server.logger.debug(line)

                    self.request.sendall("250 OK\r\n")

                else:
                    self.request.sendall("503 Command not supported\r\n")

        except socket.timeout:
            self.server.logger.warning('Connection timeout')
            
        except socket.error as msg:
            self.server.logger.error('Error: %s', msg.strerror or msg)

        except Exception, e:
            self.server.logger.error('Error: %s', e)

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

###############################################################################
# Testing code
def test(config):

    import smtplib

    logger = logging.getLogger('SMTPListenerTest')

    server = smtplib.SMTP_SSL('localhost', config.get('port', 25))

    message = "From: test@test.com\r\nTo: test@test.com\r\n\r\nTest message\r\n"

    logger.info('Testing email request.')
    logger.info('-'*80)
    server.set_debuglevel(1)
    server.sendmail('test@test.com','test@test.com', message)
    server.quit()
    logger.info('-'*80)

def main():
    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)

    config = {'port': '25', 'usessl': 'Yes', 'timeout': 10 }

    listener = SMTPListener(config)
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
