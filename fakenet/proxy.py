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
import hexdump

BUF_SZ = 4096
IP = '192.168.105.131'

logger = logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger.setLevel(logging.DEBUG)

def load_plugins(path='listeners'):
    
    plugins = []
    
    sys.path.insert(0, path)

    for plugin_modulename in glob.glob('{}/*.py'.format(path)):
        if 'HTTP' in plugin_modulename or 'Raw' in plugin_modulename:
            x = importlib.import_module( plugin_modulename[len(path)+1:-3] )
            plugins.append(x)

    return plugins


class ThreadedClientSocket(threading.Thread):


    def __init__(self, ip, port, listener_q, remote_q):

        super(ThreadedClientSocket, self).__init__()
        self.ip = ip
        self.port = int(port)
        self.listener_q = listener_q
        self.remote_q = remote_q
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):

        logger.debug('ThreadedClientSocket started')
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
            logger.debug('Listener socket exception %s' % e.message)

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    
    def handle(self):

        logger.debug('Handling TCP request')

        remote_sock = self.request
        # queue for data received from the listener
        listener_q = Queue.Queue()
        # queue for data received from remote
        remote_q = Queue.Queue()
        data = None

        ssl_remote_sock = None
        ssl_config = { 
                'certfile': 'ssl_utils/server.pem', 
                'keyfile': 'ssl_utils/privkey.pem',
                'ssl_version' : ssl.PROTOCOL_SSLv23 }

        try:
            data = remote_sock.recv(BUF_SZ, socket.MSG_PEEK)
            logger.debug('Received data\n%s' % hexdump.hexdump(data, 
                result='return'))
        except Exception as e:
            logger.info('recv() error: %s' % e.message)

        if data:

            if ssl_detector.looks_like_ssl(data):
                logger.debug('SSL detected')
                ssl_remote_sock = ssl.wrap_socket(
                        remote_sock, 
                        server_side=True, 
                        do_handshake_on_connect=True,
                        certfile=ssl_config['certfile'], 
                        ssl_version=ssl_config['ssl_version'],
                        keyfile=ssl_config['keyfile'] )
                
            top_listener = None
            top_confidence = 0

            for listener in listeners:
                confidence = listener.taste(data)
                logger.debug('Checking listener %s. Confidence: %s' % (
                    listener.NAME, confidence))
                if confidence > top_confidence:
                    top_confidence = confidence
                    top_listener = listener

            if top_listener:
                logger.debug('Likely listener: %s' % top_listener.NAME)
                listener_sock = ThreadedClientSocket('localhost', 
                        top_listener.PORT, listener_q, remote_q)
                listener_sock.setDaemon(True)
                listener_sock.start()
                remote_sock.setblocking(0)
                if ssl_remote_sock:
                    ssl_remote_sock.setblocking(0)
                while True:
                    readable, writable, exceptional = select.select(
                            [remote_sock], [], [], .001)
                    if readable:
                        if ssl_remote_sock:
                            data = ssl_remote_sock.recv(BUF_SZ)
                        else:
                            data = remote_sock.recv(BUF_SZ)
                        if data:
                            remote_q.put(data)
                        else:
                            logger.debug('Closing remote socket connection')
                            return
                    if not listener_q.empty():
                        data = listener_q.get()
                        if ssl_remote_sock:
                            ssl_remote_sock.send(data)
                        else:
                            remote_sock.send(data)

def main():

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
        logger.info('Closing proxy')
        exit(1)
    logger.info('Exiting')
    TCP_server.shutdown()

if __name__ == '__main__':
    main()
