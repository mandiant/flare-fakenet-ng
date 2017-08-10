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
import simssl
from OpenSSL import SSL

BUF_SZ = 4096
IP = '192.168.105.131'

global listeners 

def load_plugins(path='listeners'):
    
    plugins = []
    
    sys.path.insert(0, path)

    for plugin_modulename in glob.glob('{}/*.py'.format(path)):
        if 'HTTP' in plugin_modulename or 'Raw' in plugin_modulename:
            x = importlib.import_module( plugin_modulename[len(path)+1:-3] )
            plugins.append(x)

    return plugins

def looks_like_ssl(data):

    size = len(data)

    valid_versions = { 
    'SSLV3'   : 0x300,
    'TLSV1'   : 0x301,
    'TLSV1_1' : 0x302,
    'TLSv1_2' : 0x303
    }

    content_types = {
    'ChangeCipherSpec'  : 0x14,
    'Alert'             : 0x15,
    'Handshake'         : 0x16,
    'Application'       : 0x17,
    'Heartbeat'         : 0x18
    }

    handshake_message_types = {
    'HelloRequest'      : 0x00,
    'ClientHello'       : 0x01,
    'ServerHello'       : 0x02,
    'NewSessionTicket'  : 0x04,
    'Certificate'       : 0x0B,
    'ServerKeyExchange' : 0x0C,
    'CertificateRequest': 0x0D,
    'ServerHelloDone'   : 0x0E,
    'CertificateVerify' : 0x0F,
    'ClientKeyExchange' : 0x10,
    'Finished'          : 0x14
    }

    if size < 10:
        return False

    if ord(data[0]) not in content_types.values():
        return False

    if ord(data[0]) == content_types['Handshake']:
        if ord(data[5]) not in handshake_message_types.values():
            return False
        else:
            return True

    ssl_version = ord(data[1]) << 8 | ord(data[2])
    if ssl_version not in valid_versions.values():
        return False

    #check for sslv2. Need more than 1 byte however
    #if data[0] == 0x80:
    #    self.logger.info('May have detected SSLv2')
    #    return hdr_modified

    return True

class ThreadedClientSocket(threading.Thread):


    def __init__(self, ip, port, listener_q, remote_q):

        super(ThreadedClientSocket, self).__init__()
        self.ip = ip
        self.port = int(port)
        self.listener_q = listener_q
        self.remote_q = remote_q
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):

        print 'run ThreadedClientSocket'
        try:
            print 'connecting to listener socket'
            self.sock.connect((self.ip, self.port))
            while True:
                readable, writable, exceptional = select.select([self.sock], 
                        [], [], .001)
                if not self.remote_q.empty():
                    print 'pulling from remote q'
                    data = self.remote_q.get()
                    print 'data from remote q', data
                    self.sock.send(data)
                    print 'sent data to listener sock'
                if readable:
                    #print 'receiving data from listener sock'
                    data = self.sock.recv(BUF_SZ)
                    #print 'data from listener sock', data
                    if data:
                        print 'putting data on listener q'
                        self.listener_q.put(data)
                    #else:
                    #    print 'closing listener socket connection?'
                    #    self.sock.close()
                    #    exit(1)
        except Exception as e:
            print 'Listener socket exception', e

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

def handshake(s):

    while True:
        try:
            s.do_handshake()
            break
        except ssl.SSLError as err:
            if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                select.select([s], [], [])
            elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                select.select([], [s], [])
            else:
                raise

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    
    def handle(self):

        print 'Handling TCP request'

        remote_sock = self.request
        # queue for data received from the listener
        listener_q = Queue.Queue()
        # queue for data received from remote
        remote_q = Queue.Queue()
        data = None
        ssl_remote_sock = None
        
        try:
            data = remote_sock.recv(BUF_SZ, socket.MSG_PEEK)
            print 'Received data:', data
        except Exception as e:
            print 'recv error', e.message

        if data:
            print 'checking for ssl'
            if looks_like_ssl(data):
                print 'looks like ssl'
                
                print 'remote sock before wrap', remote_sock

                ssl_remote_sock = ssl.wrap_socket(remote_sock, server_side=True, 
                        certfile='server.pem', do_handshake_on_connect=True,
                        ssl_version=ssl.PROTOCOL_SSLv23, keyfile='privkey.pem')
                #handshake(ssl_remote_sock)
                
                print 'ssl remote sock after wrap', ssl_remote_sock

            top_listener = None
            top_confidence = 0

            for listener in listeners:
                confidence = listener.taste(data)
                print 'checking listener', listener.NAME, confidence
                if confidence > top_confidence:
                    top_confidence = confidence
                    top_listener = listener

            if top_listener:
                print 'top listener', top_listener.NAME
                listener_sock = ThreadedClientSocket('localhost', 
                        top_listener.PORT, listener_q, remote_q)
                listener_sock.setDaemon(True)
                listener_sock.start()
                remote_sock.setblocking(0)
                ssl_remote_sock.setblocking(0)
                while True:
                    readable, writable, exceptional = select.select(
                            [remote_sock], [], [], .001)
                    if readable:
                        try:
                            if ssl_remote_sock:
                                data = ssl_remote_sock.recv(BUF_SZ)
                            else:
                                data = remote_sock.recv(BUF_SZ)
                            #print 'data received from remote sock', data
                        except ssl.SSLError as e:
                            print 'ssl exception', e, e.errno
                            if e.errno != ssl.SSL_ERROR_WANT_READ:
                                raise
                            continue
                        if data:
                            remote_q.put(data)
                            print 'data put on remote q', data
                        #else:
                        #    print 'closing remote socket connection?'
                        #    return
                    if not listener_q.empty():
                        data = listener_q.get()
                        if ssl_remote_sock:
                            ssl_remote_sock.send(data)
                        else:
                            remote_sock.send(data)

                
def main():

    

    global listeners
    listeners = load_plugins()
    print 'listeners loaded'
    TCP_server = ThreadedTCPServer((IP, int(sys.argv[1])), ThreadedTCPRequestHandler)
    TCP_server_thread = threading.Thread(target=TCP_server.serve_forever)
    TCP_server_thread.daemon = True
    TCP_server_thread.start()
    tcp_server_ip, tcp_server_port = TCP_server.server_address
    print("TCP Server loop running (%s:%d) thread: %s" % (tcp_server_ip,
        tcp_server_port,
        TCP_server_thread.name))

    try:
        while True:
            time.sleep(.001)
    except Exception as e:
        print 'exception', e
        TCP_server.shutdown()
    #finally:
    #    print 'closing proxy'
    #    exit(1)
    #    TCP_server_thread.join()
    #    print 'proxy closed'
    print 'exiting'
    TCP_server.shutdown()


if __name__ == '__main__':
    main()
