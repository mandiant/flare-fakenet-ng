import socket
import SocketServer
import threading
import sys
import glob
import time
import importlib
import Queue
import select

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
                        print 'closing listener socket connection'
                        self.sock.close()
                        exit(1)
        except Exception as e:
            print 'Listener socket exception', e

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    
    def handle(self):

        print 'Handling TCP request'

        remote_sock = self.request
        remote_sock.setblocking(0)
        # queue for data received from the listener
        listener_q = Queue.Queue()
        # queue for data received from remote
        remote_q = Queue.Queue()
        
        try:
            data = remote_sock.recv(BUF_SZ, socket.MSG_PEEK)
            print 'Received data:', data
        except Exception as e:
            print 'recv error', e.message

        top_listener = None
        top_confidence = 0

        for listener in listeners:
            print 'checking listener', listener.NAME
            confidence = listener.taste(data)
            print 'confidence', confidence
            if confidence > top_confidence:
                top_confidence = confidence
                top_listener = listener

        if top_listener:
            print 'top listener', top_listener.NAME
            listener_sock = ThreadedClientSocket('localhost', 
                    top_listener.PORT, listener_q, remote_q)
            listener_sock.setDaemon(True)
            listener_sock.start()
            while True:
                ready = select.select([remote_sock], [], [], .001)
                if ready[0]:
                    data = remote_sock.recv(BUF_SZ)
                    if data:
                        remote_q.put(data)
                    else:
                        print 'closing remote socket connection'
                        return
                if not listener_q.empty():
                    data = listener_q.get()
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
    print 'exiting'
    TCP_server.shutdown()


if __name__ == '__main__':
    main()
