import logging

import os
import sys

import threading
import SocketServer

import ssl
import socket


class RawListener():

    def taste(self, data, dport):
        return 1

    def __init__(self, 
            config, 
            name='RawListener', 
            logging_level=logging.INFO, 
            ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)
            
        self.config = config
        self.name = name
        self.local_ip = '0.0.0.0'
        self.server = None
        self.name = 'Raw'
        self.port = self.config.get('port', 1337)

        self.logger.info('Starting...')

        self.logger.debug('Initialized with config:')
        for key, value in config.iteritems():
            self.logger.debug('  %10s: %s', key, value)

    def start(self):

        # Start listener
        if self.config.get('protocol') != None:

            if self.config['protocol'].lower() == 'tcp':
                self.logger.debug('Starting TCP ...')
                self.server = ThreadedTCPServer((self.local_ip, int(self.config['port'])), ThreadedTCPRequestHandler)

            elif self.config['protocol'].lower() == 'udp':
                self.logger.debug('Starting UDP ...')
                self.server = ThreadedUDPServer((self.local_ip, int(self.config['port'])), ThreadedUDPRequestHandler)

            else:
                self.logger.error('Unknown protocol %s', self.config['protocol'])
                return
        else:
            self.logger.error('Protocol is not defined.')
            return

        self.server.logger = self.logger
        self.server.config = self.config

        if self.config.get('usessl') == 'Yes':
            self.logger.debug('Using SSL socket.')

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

            self.server.socket = ssl.wrap_socket(self.server.socket, keyfile=keyfile_path, certfile=certfile_path, server_side=True, ciphers='RSA')
        
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
        self.request.settimeout(int(self.server.config.get('timeout', 5)))

        try:
                
            while True:

                data = self.request.recv(1024)

                if not data:
                    break

                self.server.logger.info('Received %d bytes.', len(data))
                self.server.logger.info('%s', '-'*80)
                for line in hexdump_table(data):
                    self.server.logger.info(line)
                self.server.logger.info('%s', '-'*80,)

                self.request.sendall(data)

        except socket.timeout:
            self.server.logger.warning('Connection timeout')

        except socket.error as msg:
            self.server.logger.error('Error: %s', msg.strerror or msg)

        except Exception, e:
            self.server.logger.error('Error: %s', e)

class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):

        try:
            (data,socket) = self.request
            
            if not data:
                return

            self.server.logger.info('Received %d bytes.', len(data))
            self.server.logger.debug('%s', '-'*80,)
            for line in hexdump_table(data):
                self.server.logger.debug(line)
            self.server.logger.debug('%s', '-'*80,)

            socket.sendto(data, self.client_address)

        except socket.error as msg:
            self.server.logger.error('Error: %s', msg.strerror or msg)

        except Exception, e:
            self.server.logger.error('Error: %s', e)

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    pass

def hexdump_table(data, length=16):

    hexdump_lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_line   = ' '.join(["%02X" % ord(b) for b in chunk ] )
        ascii_line = ''.join([b if ord(b) > 31 and ord(b) < 127 else '.' for b in chunk ] )
        hexdump_lines.append("%04X: %-*s %s" % (i, length*3, hex_line, ascii_line ))
    return hexdump_lines

###############################################################################
# Testing code
def test(config):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print "\t[RawListener] Sending request:\n%s" % "HELO\n"
    try:
        # Connect to server and send data
        sock.connect(('localhost', int(config.get('port', 23))))
        sock.sendall("HELO\n")

        # Receive data from the server and shut down
        received = sock.recv(1024)
    finally:
        sock.close()

def main():
    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)

    config = {'port': '1337', 'usessl': 'No', 'protocol': 'tcp'}

    listener = RawListener(config)
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
    #test(config)

    listener.stop()

if __name__ == '__main__':
    main()
