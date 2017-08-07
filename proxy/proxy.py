import socket
import SocketServer
import threading
import sys
import importlib
import glob

import Conntrack
import logging, logger
import utils
import time

import ConfigParser

modules = []
cm = None

last_session_id = 0

def load_plugins(path="listeners"):
    
    plugins = []
    
    sys.path.insert(0, path)

    for plugin_modulename in glob.glob("{}/*.py".format(path)):
        x = importlib.import_module( plugin_modulename[len(path)+1:-3] )
        plugins.append(x)
        #log.debug("Loading plugin: %s" % x.moduleName)

    return plugins
    
def reload_plugins(mods=modules):
    
    for mod in mods:
        try:
            reload(mod)
            log.debug("Reloading plugin: %s" % mod.moduleName)
        except Exception as e:
            
            log.info("Failed to reload plugin: %s" % mod.moduleName)
            log.debug(e)


def recv_timeout(soc, timeout, bufsize=1024, flags=0):
    current_timeout = soc.gettimeout()
    soc.settimeout(timeout)
    
    try:
        buffer = soc.recv(bufsize, flags)
    except socket.timeout:
        buffer = ""
    
    soc.settimeout(current_timeout)
    
    return buffer
    

def CreateSessionID():
    global last_session_id
    session_id_lock.acquire(True)
    _now = time.time()
    
    if _now <= last_session_id:
        _now = last_session_id + .0001
    
    last_session_id = _now
    session_id_lock.release()
    
    return _now
        
class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
        
    def handle(self):
        global modules, cm
   
        IPPROTO_TCP=6 
        cur_thread = threading.current_thread()
        cur_thread.session_id = CreateSessionID()
        cur_thread.msg_count = 0
        cur_socket = self.request
                
        client_info = self.request.getpeername()

        cm_info = cm.get(IPPROTO_TCP, tcp_server_ip, client_info[0], 
        		tcp_server_port, client_info[1])

        log.info("Proto:TCP src:%s spt:%d dst:%s dpt:%d" % (cm_info["src"],
    		cm_info["spt"],cm_info["dst"], cm_info["dpt"]))
        
        cm_info["parent_module"] = None
        cm_info["modules"] = []
        cm_info["config"] = self.server.config
        
        while(cur_socket != None):

            #data = cur_socket.recv(2048, socket.MSG_PEEK)
            try:
                data = recv_timeout(cur_socket, 10, bufsize=2048, flags=socket.MSG_PEEK)
                print 'data received in threadedTCPRequestHandler'
                log.info('data received in threadedTCPRequestHandler')
            except:
                log.info("recv_time exception")
                data = ""

            theMod = None
            cur_confidence = 0
            
            for mod in modules:
                if mod.moduleProtocol != "TCP":
                    continue
            
                r = mod.taste(data, cm_info)
                
                if(r > 0):
                    log.debug( "{}: {} confidence:{}".format(cur_thread.name, mod.moduleName, r))
                    
                if(r > cur_confidence):
                	theMod = mod
                	cur_confidence = r
                	
            if theMod==None:
            	log.info("Proto:TCP src:%s spt:%d dst:%s dpt:%d" % (cm_info["src"],
            		cm_info["spt"],cm_info["dst"], cm_info["dpt"]))
            	log.info("None Mod Contents:\n %s" % (utils.dump_hex(data)))
            	break
	
            cur_socket = theMod.handle(cm_info, cur_socket, cm_info)
            
            if cur_socket != None:
                cm_info["parent_module"] = theMod
                cm_info["modules"].append(theMod)

        
class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):
        
    def handle(self):
        global modules
        
        cur_thread = threading.current_thread()
        cur_thread.session_id = CreateSessionID()
        cur_thread.msg_count = 0
        data = self.request[0]
        socket = self.request[1]
        
        IPPROTO_UDP=17

        cm_info = cm.get(IPPROTO_UDP, udp_server_ip, self.client_address[0], 
        		udp_server_port, self.client_address[1])
        		
        if(cm_info["dst"].endswith(".255")):
        #	log.debug("Filtering Proto:UDP src:%s spt:%d dst:%s dpt:%d" % (cm_info["src"],
        #		cm_info["spt"],cm_info["dst"], cm_info["dpt"]))
        	return
        	
        log.info("Proto:UDP src:%s spt:%d dst:%s dpt:%d" % (cm_info["src"],
    		cm_info["spt"],cm_info["dst"], cm_info["dpt"]))
    		        
        theMod = None
        cur_confidence = 0
        
        cm_info["config"] = self.server.config


        for mod in modules:
            if mod.moduleProtocol != "UDP":
                continue
        
            r = mod.taste(data, cm_info)
            
            if(r > 0):
                log.debug( "{}: {} confidence:{}".format(cur_thread.name, mod.moduleName, r))
            if(r > cur_confidence):
                theMod = mod
            cur_confidence = r
	    
        if theMod:
            theMod.handle(None, data, socket, self.client_address)
        
        
class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

    
class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    pass
    
    
if __name__ == "__main__":

    log = logging.getLogger('NetHandler')
    log.setLevel('DEBUG')
    #log.addHandler(logger.Logger())
    
    session_id_lock = threading.Lock()
    cur_thread = threading.current_thread()
    cur_thread.session_id = CreateSessionID()
    cur_thread.msg_count = 0
        
    config_ini = ConfigParser.RawConfigParser()
    config_ini.read('config/config.ini')
    config = {}
    
    for c in config_ini.sections():
    	config[c] = dict(config_ini.items(c))
    
    tcp_server_ip = config["TCP Server"]["ip"]
    tcp_server_port = int(config["TCP Server"]["port"])
    
    udp_server_ip = config["UDP Server"]["ip"]
    udp_server_port = int(config["UDP Server"]["port"])
    
    #if config.has_key("Default Files"):
    #    for d in config["Default Files"]:
    #        try:
    #            config["Default Files"][d] = open(config["Default Files"][d], "rb").read()
    #        except:
    #            print "Failed to open default file [%s] %s" % (d, config["Default Files"][d])
        
    
    modules = load_plugins()
    
    cm = Conntrack.ConnectionManager()

    TCP_server = ThreadedTCPServer((tcp_server_ip, tcp_server_port), ThreadedTCPRequestHandler)
    #tcp_server_ip, tcp_server_port = TCP_server.server_address
    
    TCP_server_thread = threading.Thread(target=TCP_server.serve_forever)
    TCP_server_thread.daemon = True
    TCP_server.config = config
    TCP_server_thread.start()
    
    log.info("TCP Server loop running (%s:%d) thread: %s" % (tcp_server_ip,
    	tcp_server_port,
    	TCP_server_thread.name))
    
    UDP_server = ThreadedUDPServer((udp_server_ip, udp_server_port), ThreadedUDPRequestHandler)
    udp_server_ip, udp_server_port = UDP_server.server_address
    UDP_server_thread = threading.Thread(target=UDP_server.serve_forever)
    UDP_server_thread.daemon = True
    UDP_server.config = config
    UDP_server_thread.start()
    
    log.info("UDP Server loop running (%s:%d) thread: %s" % (udp_server_ip,
    	udp_server_port,
    	UDP_server_thread.name))
    	    
    try:
        while True:
            cmd = sys.stdin.readline().strip()

            if(cmd == "reload"):
                reload_plugins(modules)
            elif (cmd == "exit"):
                break
            else:
                print "Unknown cmd: %s" % cmd
    except:
    	print "Exception"
        TCP_server.shutdown()
        UDP_server.shutdown()
        exit(-1)
    TCP_server.shutdown()
    UDP_server.shutdown()
