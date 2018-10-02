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
import traceback
from OpenSSL import SSL
from ssl_utils import ssl_detector
from . import *
import os

BUF_SZ = 1024
IP = '0.0.0.0'

class ProxyListener(object):


    def __init__(
            self,
            config={},
            name ='ProxyListener',
            logging_level=logging.DEBUG,
            ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)

        self.config = config
        self.name = name
        self.server = None
        self.udp_fwd_table = dict()

        self.logger.info('Starting...')

        self.logger.debug('Initialized with config:')
        for key, value in config.iteritems():
            self.logger.debug('  %10s: %s', key, value)

    def start(self):

        proto = self.config.get('protocol').upper()
        if proto != None:

            if proto == 'TCP':

                self.logger.debug('Starting TCP ...')

                self.server = ThreadedTCPServer((IP,
                    int(self.config.get('port'))), ThreadedTCPRequestHandler)

            elif proto == 'UDP':

                self.logger.debug('Starting UDP ...')

                self.server = ThreadedUDPServer((IP,
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
        self.server.running_listeners = None
        self.server.diverter = None
        self.server_thread = threading.Thread(
                target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        server_ip, server_port = self.server.server_address
        self.logger.info("%s Server(%s:%d) thread: %s" % (proto, server_ip,
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

        self.timeout = 3
        self.select_timeout = 0.001
        self.is_running = True

        remote_sock = self.request
        # queue for data received from the listener
        listener_q = Queue.Queue()
        # queue for data received from remote
        remote_q = Queue.Queue()

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


        try:
            data = remote_sock.recv(BUF_SZ, socket.MSG_PEEK)
            log_details(self.server.logger, data)
        except Exception as e:
            data = ''
            self.server.logger.info('recv() error: %s' % e.message)

        if not data:
            return


        if ssl_detector.looks_like_ssl(data):
            self.server.logger.debug('SSL detected')
            ssl_remote_sock = ssl.wrap_socket(
                    remote_sock,
                    server_side=True,
                    do_handshake_on_connect=True,
                    certfile=certfile_path,
                    ssl_version=ssl.PROTOCOL_SSLv23,
                    keyfile=keyfile_path )
            data = ssl_remote_sock.recv(BUF_SZ)

        top_listener = get_top_listener(self.server.config, data,
                self.server.listeners, self.server.diverter,
                self.client_address[0], self.client_address[1], 'TCP')

        if not top_listener:
            return

        self.server.logger.debug('Likely listener: %s' % top_listener.name)
        remote_sock.setblocking(0)

        # ssl has no 'peek' option, so we need to process the first
        # packet that is already consumed from the socket
        if ssl_remote_sock:
            ssl_remote_sock.setblocking(0)
            remote_q.put(data)

        data_available = threading.Event()

        # Try to connect to listener socket
        lsocket = self.connect_to_listener('localhost', int(top_listener.port))
        if lsocket is None:
            self.server.logger.error('Failed to connect to listener socket')
            return

        threading.Thread(target=self.receive_data, args=[
            lsocket,                # listener socket
            listener_q,             # data queue
            data_available,         # event
        ]).start()

        rsocket = remote_sock if ssl_remote_sock is None else ssl_remote_sock
        threading.Thread(target=self.receive_data, args=[
            rsocket,                # remote socket
            remote_q,               # queue
            data_available          # event
        ]).start()

        self.proxy(rsocket, lsocket, remote_q, listener_q, data_available)
        lsocket.close()
        rsocket.close()
        return

    def proxy(self, rsocket, lsocket, rq, lq, ev):
        try:
            while self.is_running:
                while not rq.empty():
                    data = rq.get()
                    lsocket.send(data)
                while not lq.empty():
                    data = lq.get()
                    rsocket.send(data)
                ev.clear()
                if not ev.wait(timeout=self.timeout):
                    self.is_running = False
                    break
        except Exception as e:
            self.server.logger.error('Failed to proxy data')
            self.server.logger.debug(traceback.format_exc())
        return

    def receive_data(self, s, q, ev):
        try:
            while self.is_running:
                readable, writable, exceptional = select.select([s], [], [], self.select_timeout)
                if readable:
                    data = s.recv(BUF_SZ)
                    if data:
                        q.put(data, block=True)
                        ev.set()
                    else:
                        s.close()
                        break
        except Exception as e:
            self.server.logger.error('Exception when trying to receive data')
            self.server.logger.debug(e.message)

        # Always set the last event to have the main loop wake up
        ev.set()
        return

    def connect_to_listener(self, host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
        except Exception as e:
            s = None
            self.server.logger.error('Failed to connect to listener')
            self.server.logger.error(e.message)
        return s


class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):


    def handle(self):
        data = self.request[0]
        remote_sock = self.request[1]

        self.server.logger.debug('Received UDP packet from %s.' %
                self.client_address[0])

        if data:

            self.server.logger.info('Received %d bytes.', len(data))
            log_details(self.server.logger, data)

            orig_src_ip = self.client_address[0]
            orig_src_port = self.client_address[1]

            top_listener = get_top_listener(self.server.config, data,
                    self.server.listeners, self.server.diverter,
                    orig_src_ip, orig_src_port, 'UDP')

            if top_listener:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('localhost', 0))

                sock.sendto(data, ('localhost', int(top_listener.port)))
                reply = sock.recv(BUF_SZ)
                self.server.logger.info('Received %d bytes.', len(data))
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


def log_details(logger, data):
    logger.info('Received %d bytes.', len(data))
    logger.debug('%s', '-'*80,)
    for line in hexdump_table(data):
        logger.debug(line)
    logger.debug('%s', '-'*80,)
    return


def main():

    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s',
            datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)
    global listeners
    listeners = load_plugins()

    TCP_server = ThreadedTCPServer((IP, int(sys.argv[1])),
            ThreadedTCPRequestHandler)
    TCP_server_thread = threading.Thread(target=TCP_server.serve_forever)
    TCP_server_thread.daemon = True
    TCP_server_thread.start()
    tcp_server_ip, tcp_server_port = TCP_server.server_address
    logger.info("TCP Server(%s:%d) thread: %s" % (tcp_server_ip,
        tcp_server_port, TCP_server_thread.name))

    try:
        while True:
            time.sleep(.001)
    except Exception as e:
        logger.info(e)
        TCP_server.shutdown()
    finally:
        logger.info('Closing ProxyListener')
        exit(1)
    logger.info('Exiting')
    TCP_server.shutdown()

if __name__ == '__main__':
    main()
