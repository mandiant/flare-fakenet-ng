import socket
import SocketServer
import threading
import sys
import glob
import time
import importlib
import Queue
import select
import logging
import ssl
from OpenSSL import SSL
from ssl_utils import ssl_detector
from . import *
import os

BUF_SZ = 1024

class ProxyListener(object):


    def __init__(
            self,
            config={},
            name='ProxyListener',
            logging_level=logging.DEBUG,
            ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)

        self.config = config
        self.name = name
        self.local_ip = config.get('ipaddr')
        self.server = None
        self.udp_fwd_table = dict()

        self.logger.debug('Starting...')

        self.logger.debug('Initialized with config:')
        for key, value in config.iteritems():
            self.logger.debug('  %10s: %s', key, value)

    def start(self):

        proto = self.config.get('protocol').upper()
        if proto != None:

            if proto == 'TCP':

                self.logger.debug('Starting TCP ...')

                self.server = ThreadedTCPServer((self.local_ip,
                    int(self.config.get('port'))), ThreadedTCPRequestHandler)

            elif proto == 'UDP':

                self.logger.debug('Starting UDP ...')

                self.server = ThreadedUDPServer((self.local_ip,
                    int(self.config.get('port'))), ThreadedUDPRequestHandler)
                self.server.fwd_table = self.udp_fwd_table

            else:
                self.logger.error('Unknown protocol %s' % proto)
                return

        else:
            self.logger.error('Protocol is not defined')
            return

        self.server.config = self.config
        self.server.logger = self.logger
        self.server.local_ip = self.local_ip
        if self.local_ip == '0.0.0.0':
            self.server.local_ip = 'localhost'
        self.server.running_listeners = None
        self.server.diverter = None
        self.server_thread = threading.Thread(
                target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        server_ip, server_port = self.server.server_address
        self.logger.debug("%s Server(%s:%d) thread: %s" % (proto, server_ip,
            server_port, self.server_thread.name))

    def stop(self):
        self.logger.debug('Stopping...')
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def acceptListeners(self, listeners):
        self.server.listeners = listeners

    def acceptDiverter(self, diverter):
        self.server.diverter = diverter

class ThreadedTCPClientSocket(threading.Thread):


    def __init__(self, ip, port, listener_q, remote_q, config, log):

        super(ThreadedTCPClientSocket, self).__init__()
        self.ip = ip
        self.port = int(port)
        self.listener_q = listener_q
        self.remote_q = remote_q
        self.config = config
        self.logger = log
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):

        try:
            self.sock.connect((self.ip, self.port))
            while True:
                readable, writable, exceptional = select.select([self.sock],
                        [], [], .001)
                if not self.remote_q.empty():
                    data = self.remote_q.get()
                    self.sock.send(data)
                if readable:
                    data = self.sock.recv(BUF_SZ)
                    if data:
                        self.listener_q.put(data)
                    else:
                        self.sock.close()
                        exit(1)
        except Exception as e:
            self.logger.debug('Listener socket exception %s' % e.message)

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    daemon_threads = True

class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    daemon_threads = True

def get_top_listener(config, data, listeners, diverter, orig_src_ip,
        orig_src_port, proto):
    

    top_listener = None
    top_confidence = 0
    dport = diverter.getOriginalDestPort(orig_src_ip, orig_src_port, proto)

    for listener in listeners:
  
        try:
            confidence = listener.taste(data, dport)
            if confidence > top_confidence:
                top_confidence = confidence
                top_listener = listener
        except:
            # Exception occurs if taste() is not implemented for this listener
            pass
    
    return top_listener

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    
    def handle(self):

        remote_sock = self.request
        # queue for data received from the listener
        listener_q = Queue.Queue()
        # queue for data received from remote
        remote_q = Queue.Queue()
        data = None

        ssl_remote_sock = None

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

        ssl_version = ssl.PROTOCOL_SSLv23

        try:
            data = remote_sock.recv(BUF_SZ, socket.MSG_PEEK)

            self.server.logger.debug('Received %d bytes.', len(data))
            self.server.logger.debug('%s', '-'*80,)
            for line in hexdump_table(data):
                self.server.logger.debug(line)
            self.server.logger.debug('%s', '-'*80,)

        except Exception as e:
            self.server.logger.warning('recv() error: %s' % e.message)

        if data:

            if ssl_detector.looks_like_ssl(data):
                self.server.logger.debug('SSL detected')
                ssl_remote_sock = ssl.wrap_socket(
                        remote_sock, 
                        server_side=True, 
                        do_handshake_on_connect=True,
                        certfile=certfile_path, 
                        ssl_version=ssl_version,
                        keyfile=keyfile_path )
                data = ssl_remote_sock.recv(BUF_SZ)
            
            orig_src_ip = self.client_address[0]
            orig_src_port = self.client_address[1]
            
            top_listener = get_top_listener(self.server.config, data,
                    self.server.listeners, self.server.diverter,
                    orig_src_ip, orig_src_port, 'TCP')

            if top_listener:
                self.server.logger.debug('Likely listener: %s' %
                                         top_listener.name)
                listener_sock = ThreadedTCPClientSocket(self.server.local_ip,
                        top_listener.port, listener_q, remote_q,
                        self.server.config, self.server.logger)
                listener_sock.daemon = True
                listener_sock.start()
                remote_sock.setblocking(0)

                # ssl has no 'peek' option, so we need to process the first
                # packet that is already consumed from the socket
                if ssl_remote_sock:
                    ssl_remote_sock.setblocking(0)
                    remote_q.put(data)
                
                while True:
                    readable, writable, exceptional = select.select(
                            [remote_sock], [], [], .001)
                    if readable:
                        try:
                            if ssl_remote_sock:
                                data = ssl_remote_sock.recv(BUF_SZ)
                            else:
                                data = remote_sock.recv(BUF_SZ)
                            if data:
                                remote_q.put(data)
                            else:
                                self.server.logger.debug(
                                        'Closing remote socket connection')
                                return
                        except Exception as e:
                            self.server.logger.debug('Remote Connection terminated')
                            return
                    if not listener_q.empty():
                        data = listener_q.get()
                        if ssl_remote_sock:
                            ssl_remote_sock.send(data)
                        else:
                            remote_sock.send(data)

class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):


    def handle(self):
        data = self.request[0]
        remote_sock = self.request[1]

        self.server.logger.debug('Received UDP packet from %s.' %
                self.client_address[0])

        if data:

            self.server.logger.debug('Received %d bytes.', len(data))
            self.server.logger.debug('%s', '-'*80,)
            for line in hexdump_table(data):
                self.server.logger.debug(line)
            self.server.logger.debug('%s', '-'*80,)

            orig_src_ip = self.client_address[0]
            orig_src_port = self.client_address[1]

            top_listener = get_top_listener(self.server.config, data,
                    self.server.listeners, self.server.diverter,
                    orig_src_ip, orig_src_port, 'UDP')

            if top_listener:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.server.local_ip, 0))

                sock.sendto(data, (self.server.local_ip, int(top_listener.port)))
                reply = sock.recv(BUF_SZ)
                self.server.logger.debug('Received %d bytes.', len(data))
                sock.close()
                remote_sock.sendto(reply, (orig_src_ip, int(orig_src_port)))
        else:
            self.server.logger.debug('No packet data')

def hexdump_table(data, length=16):

    hexdump_lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_line   = ' '.join(["%02X" % ord(b) for b in chunk ] )
        ascii_line = ''.join([b if ord(b) > 31 and ord(b) < 127 else '.' for b in chunk ] )
        hexdump_lines.append("%04X: %-*s %s" % (i, length*3, hex_line, ascii_line ))
    return hexdump_lines

def main():

    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s',
            datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)
    global listeners
    listeners = load_plugins()

    TCP_server = ThreadedTCPServer((sys.argv[1], int(sys.argv[2])),
            ThreadedTCPRequestHandler)
    TCP_server_thread = threading.Thread(target=TCP_server.serve_forever)
    TCP_server_thread.daemon = True
    TCP_server_thread.start()
    tcp_server_ip, tcp_server_port = TCP_server.server_address
    logger.debug("TCP Server(%s:%d) thread: %s" % (tcp_server_ip,
        tcp_server_port, TCP_server_thread.name))

    try:
        while True:
            time.sleep(.001)
    except Exception as e:
        logger.info(e)
        TCP_server.shutdown()
    finally:
        logger.debug('Closing ProxyListener')
        exit(1)
    logger.debug('Exiting')
    TCP_server.shutdown()

if __name__ == '__main__':
    main()
