import json
import logging
import subprocess as sp
import threading
import traceback

from scapy.all import TCP, UDP, IP

from time import sleep
from ctypes import CDLL, Structure, sizeof, byref, create_string_buffer
from ctypes import c_ubyte, c_ushort, c_int, c_uint, c_ulong, c_char, c_void_p
from socket import SOCK_STREAM

from diverters.darwin import DarwinDiverter
from diverters.darwin.pkt import DarwinKextPacketCtx

KEXT_PATH_KEY = r'darwinkextpath'
LOOPBACK_IP = '127.0.0.1'


class KextMonitor(object):
    PF_SYSTEM = 32
    SYSPROTO_CONTROL = 2
    AF_SYS_CONTROL = 2
    CTLIOCGINFO = c_ulong(3227799043)
    MYCONTROLNAME = "com.mandiant.FakeNetDiverter"
    MAX_PKT_JSON = 1024
    OPTNEXTPKT = 1
    OPTINJECTPKT = 2
    OPTDROPPKT = 3
    OPTENABLESWALLOW = 4
    OPTDISABLESWALLOW = 5
    LIB_SYSTEM_PATH = "/usr/lib/libSystem.B.dylib"
    KEXT_PATH = "/Users/me/FakeNetDiverter.kext"

    class sockaddr_ctl(Structure):
        _fields_ = [('sc_len', c_ubyte),
                    ('sc_family', c_ubyte),
                    ('ss_sysaddr', c_ushort),
                    ('sc_id', c_uint),
                    ('sc_unit', c_uint),
                    ('sc_reserved', c_uint * 5)]

    class ctl_info(Structure): 
        _fields_ = [('ctl_id', c_uint),
        ('ctl_name', c_char * 96)]
    

    def __init__(self, callback, kextpath=None):
        self.posix = None
        self.callback = callback
        self.kextpath = self.KEXT_PATH if kextpath is None else kextpath
        self.timeout = 3
        self.logger = logging.getLogger('Diverter.Darwin.KextMonitor')
    
    def __del__(self):
        self.__unload_kext()

    def initialize(self):
        self.posix = self.__initialize_posix_wrapper()
        if self.posix is None:
            self.logger.error('Failed to initialize POSIX wrapper')
            return False

        if not self.__load_kext():
            self.logger.error('Failed to load kernel extension')
            return False

        return True
    
    def start(self):
        self.is_running = True
        self.socket = self.__initialize_socket()

        if self.socket is None:
            return False
        
        e = threading.Event()
        e.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_thread,
                                               args=[e])
        self.monitor_thread.start()
        rc = e.wait(self.timeout)
        return rc
    
    def stop(self):
        self.is_running = False
        if self.monitor_thread is None:
            return True
        rc = self.monitor_thread.join(self.timeout)
        self.posix.close(self.socket)
        self.socket = None
        self.posix = None
        self.__unload_kext()
        return rc

    # internal
    def __initialize_posix_wrapper(self):
        posix = CDLL(self.LIB_SYSTEM_PATH, use_errno=True)
        posix.getsockopt.argtypes = [c_int, c_int, c_int, c_void_p, c_void_p]
        posix.setsockopt.argtypes = [c_int, c_int, c_int, c_void_p, c_uint]
        return posix

    def __initialize_socket(self):
        posix = self.posix
        if posix is None:
            return None
        socket = posix.socket(
            self.PF_SYSTEM, SOCK_STREAM, self.SYSPROTO_CONTROL)

        addr = self.sockaddr_ctl()
        addr.sc_len = (c_ubyte)(sizeof(self.sockaddr_ctl))
        addr.sc_family = (c_ubyte)(self.PF_SYSTEM)
        addr.ss_sysaddr = (c_ushort)(self.AF_SYS_CONTROL)

        info = self.ctl_info()
        info.ctl_name = self.MYCONTROLNAME

        rc = posix.ioctl(socket, self.CTLIOCGINFO, byref(info))        

        addr.sc_id = (c_uint)(info.ctl_id)
        addr.sc_unit = (c_uint)(0)
        posix.connect(socket, byref(addr), sizeof(addr))
        return socket
    
    def __load_kext(self):
        try:
            sp.call("kextutil %s" % (self.kextpath,), shell=True)
        except:
            return False
        return True

    def __unload_kext(self):
        if self.socket is not None and self.posix is not None:
            self.posix.close(self.socket)
            self.posix = None
            self.socket = None

        count = 2
        while count > 0:
            try:
                self.logger.error("Unloading kext...")
                x = sp.call("kextunload %s" % (self.kextpath,), shell=True)
            except:
                return False
            sleep(1)
            count -= 1
        return True
    

    def _monitor_thread(self, event):
        event.set()
        self.posix.setsockopt(
            self.socket, self.SYSPROTO_CONTROL, self.OPTENABLESWALLOW, 0, 0)

        while self.is_running:
            pktSize = c_uint(self.MAX_PKT_JSON)
            pkt = create_string_buffer("\x00" * self.MAX_PKT_JSON)
            self.posix.getsockopt(self.socket,
                                  self.SYSPROTO_CONTROL,
                                  self.OPTNEXTPKT, pkt, byref(pktSize))

            try:
                if len(pkt.value) > 0:
                    pktjson = json.loads(pkt.value)
                    newpkt = self.__process(pktjson)
                    if newpkt is None:
                        pkt = byref(c_uint(int(pktjson.get('id'))))
                        pktSize = c_uint(4)
                        self.posix.setsockopt(self.socket,
                                              self.SYSPROTO_CONTROL,
                                              self.OPTDROPPKT, pkt, pktSize)
                    newjson = json.dumps(newpkt)
                    newjson += '\0x00'
                    newpkt = create_string_buffer(newjson)

                    pktSize = c_uint(len(newpkt))

                    self.posix.setsockopt(self.socket,
                                          self.SYSPROTO_CONTROL,
                                          self.OPTINJECTPKT, newpkt, pktSize)
            except:
                fmt = traceback.format_exc()
                self.logger.debug('Failed to process packet')
                self.logger.debug(fmt)
                continue
        self.posix.setsockopt(self.socket,
                              self.SYSPROTO_CONTROL,
                              self.OPTDISABLESWALLOW, 0, 0)
        return

    def __process(self, pkt):
        ip_packet = self.ip_packet_from_json(pkt)
        if ip_packet is None:
            return None

        # Process the packet through the callbacks. pctx is updated as it
        # traverse through the callback stack
        pctx = DarwinKextPacketCtx(pkt, 'DarwinKextPacket', ip_packet)
        self.callback(pctx)
        if not pctx.mangled:
            newpkt = {'id': pctx.meta.get('id'), 'changed': False}
        else:
            newpkt = self.json_from_pctx(pctx)
        return newpkt
    
    def ip_packet_from_json(self, js):
        proto = js.get('proto', None)
        sport = js.get('srcport')
        dport = js.get('dstport')
        src = js.get('srcaddr')
        dst = js.get('dstaddr')
        
        if proto is None or sport is None or dport is None:
            return None
        
        if  src is None or dst is None:
            return None
        
        if proto == 'tcp':
            tport = TCP(sport=sport, dport=dport)
        elif proto == 'udp':
            tport = UDP(sport=sport, dport=dport)
        else:
            tport is None        
        if tport is None:
            return None
        
        ip_packet = IP(src=src, dst=dst)/tport
        return ip_packet
    
    def json_from_pctx(self, pctx):
        return {
            u'id': pctx.meta.get('id'),
            u'direction': pctx.meta.get('direction'),
            u'proto': pctx.protocol,
            u'srcaddr': pctx.src_ip,
            u'srcport': pctx.sport,
            u'dstaddr': pctx.dst_ip,
            u'dstport': pctx.dport,
            u'ip_ver': pctx.meta.get('ip_ver'),
            u'changed': pctx.mangled
        }
    
    def drop(self, pkt):
        pkt = byref(c_uint(int(pkt.get('id', -1))))
        pktSize = c_uint(4)
        self.posix.setsockopt(self.socket, self.SYSPROTO_CONTROL,
                              self.OPTDROPPKT, pkt, pktSize)
        return True



class KextDiverter(DarwinDiverter):
    def __init__(self, diverter_config, listeners_config, ip_addrs, log_level):
        super(KextDiverter, self).__init__(diverter_config, listeners_config,
                                           ip_addrs, log_level)
        self.kextpath = diverter_config.get(KEXT_PATH_KEY, None)
        self.monitor = None
        self.initialize()
    
    def initialize(self):
        self.monitor = KextMonitor(self.handle_packet, self.kextpath)
        if not self.monitor.initialize():
            self.monitor = None
            raise NameError("Failed to initialize monitor")
        return True
    
    def handle_packet(self, pctx):
        direction = pctx.meta.get('direction')
        cb3 = [
            self.check_log_icmp   
        ]

        if direction == 'out':
            cb4 = [
                self.maybe_redir_ip,
                self.maybe_redir_port,
            ]
        else:
            cb4 = [
                self.maybe_fixup_sport,
                self.maybe_fixup_srcip,
            ]
        self.handle_pkt_wrap(pctx, cb3, cb4)
        return 
    
    def handle_pkt_wrap(self, pctx, cb3, cb4):
        self.handle_pkt(pctx, cb3, cb4)
        return

    def get_pid_comm(self, pkt):
        return pkt.meta.get('pid', ''), pkt.meta.get('procname', '')
    
    def startCallback(self):
        self.monitor.start()
        return True
    
    def stopCallback(self):
        self.monitor.stop()
        return
    
    def getNewDestinationIp(self, ip):
        return LOOPBACK_IP