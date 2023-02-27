import Queue
import logging
import netifaces
import threading
import pcapy
import traceback
import subprocess as sp

from scapy.all import Ether, IP, conf, TCP, UDP, sendp
from expiringdict import ExpiringDict
from diverters.debuglevels import *
from diverters import fnpacket
from diverters.darwin import DarwinDiverter
from diverters.darwin.pkt import DarwinPacketCtx


ADDR_LINK_ANY = 'ff:ff:ff:ff:ff:ff'
LOOPBACK_IP = '127.0.0.1'
MY_IP = '192.0.3.123'
MY_IP_FAKE = '192.0.3.124'
LOOPBACK_IFACE = 'lo0'



class Injector(object):
    '''
    Handle traffic injection to either a loopback interface or a real interface
    '''
    LOOPBACK_BYTE_HEADER = '\x02\x00\x00\x00'
    def __init__(self):
        super(Injector, self).__init__()
        self.iface = None
        self.is_loopback = True

    def initialize(self, iface):
        '''
        Initialize the Injector. Also do some quick validation to make sure
        the iface object contains enough information
        @param iface = {
            'iface'      :   <interface name>
            'dlinkdst'  :   required for none loopback: gateway hardware addr.
            'dlinksrc'  :   required for none loopback: iface hardware addr.
        }
        '''
        name = iface.get('iface')
        if name is None:
            return False

        self.is_loopback = name == 'lo0'

        if not self.is_loopback:
            dlinksrc = iface.get('dlinksrc')
            dlinkdst = iface.get('dlinkdst')
            if dlinksrc is None or dlinkdst is None:
                return False

        self.iface = iface
        return True

    def inject(self, bytez):
        '''
        Inject bytes into an interface without any validation
        '''
        if self.is_loopback:
            bytez = self.LOOPBACK_BYTE_HEADER + str(bytez)
        else:
            bytez = Ether(src=self.iface.get('dlinksrc'),
                          dst=self.iface.get('dlinkdst'))/bytez
        sendp(bytez, iface=self.iface.get('iface'), verbose=False)


class InterfaceMonitor(object):
    TIMEOUT = 3
    QUEUESIZE = 0xfff
    QUEUE_TIMEOUT = 1
    WORKER_THREADS = 0x03
    def __init__(self, ifname, callback):
        self.monitor_thread = None
        self.is_running = False
        self.timeout = self.TIMEOUT
        self.iface = ifname
        self.callback = callback
        self.logger = logging.getLogger('Diverter.Darwin.IfaceMonitor')
        self.queue = Queue.Queue(self.QUEUESIZE)


    def start(self):
        e = threading.Event()
        e.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_thread,
                                               args=[e])
        self.is_running = True
        self.monitor_thread.start()
        rc = e.wait(self.timeout)

        # start a bunch of worker threads
        for i in xrange(self.WORKER_THREADS):
            threading.Thread(target=self._process_thread).start()
        return rc

    def stop(self):
        self.is_running = False
        if self.monitor_thread is None:
            return True
        rc = self.monitor_thread.join(self.timeout)
        return rc

    def _monitor_thread(self, e):
        try:
            self.logger.error('Monitoring %s' % self.iface)
            pc = pcapy.open_live(self.iface, 0xffff, 1, 1)
        except:
            err = traceback.format_exc()
            self.logger.error(err)
            self.is_running = False
            return
        e.set()
        while self.is_running:
            _ts, bytez = pc.next()
            self._enqueue(bytez)
        self.logger.error('monitor thread stopping')
        return

    def _enqueue(self, bytez):
        ip_packet = self.ip_packet_from_bytes(bytez)
        if ip_packet is None:
            return False

        pkt = DarwinPacketCtx('DarwinPacket', ip_packet)
        self.queue.put(pkt)
        return

    def _process_thread(self):
        while self.is_running:
            try:
                pkt = self.queue.get(timeout=self.QUEUE_TIMEOUT)
            except Queue.Empty:
                continue
            self.callback(pkt)
        return

    def ip_packet_from_bytes(self, bytez):
        if self.iface.startswith('lo'):
            return self._ip_packet_from_bytes_loopback(bytez)
        return self._ip_packet_from_bytes(bytez)

    def _ip_packet_from_bytes(self, bytez):
        if len(bytez) <= 0:
            return None
        try:
            eframe = Ether(bytez)
            ipkt = eframe[IP]
        except:
            return None
        return ipkt

    def _ip_packet_from_bytes_loopback(self, bytez):
        if len(bytez) <= 0:
            return None

        try:
            ip_packet = IP(bytez[4:])
        except:
            err = traceback.format_exc()
            self.logger.error('Failed to process packet: %s' % (err,))
            return None
        return ip_packet



class UsermodeDiverter(DarwinDiverter):
    LOOPBACK_IFACE = 'lo0'
    def __init__(self, diverter_config, listeners_config, ip_addrs,
                 logging_level=logging.INFO):
        super(UsermodeDiverter, self).__init__(diverter_config, listeners_config,
                                       ip_addrs, logging_level)

        self.loopback_ip = MY_IP
        self.loopback_ip_fake = MY_IP_FAKE
        self.devnull = open('/dev/null', 'rw+')

        self.configs = dict()
        self.is_running = False
        self.iface_monitor = None
        self.loopback_monitor = None
        self.inject_cache = ExpiringDict(max_age_seconds=10, max_len=0xfff)
        self.initialize()

        # hide scappy noisy logs
        logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

    def initialize(self):
        super(UsermodeDiverter, self).initialize()

        # initialize a loopback injector
        self.loopback_injector = Injector()
        if not self.loopback_injector.initialize({'iface': 'lo0'}):
            raise NameError("Failed to initialize loopback injector")

        # initialize main injector
        self.injector = Injector()
        iface = {
            'iface': self.iface.get('iface'),
            'dlinksrc': self.iface.get('addr.dlink'),
            'dlinkdst': self.gw.get('addr.dlink')
        }
        if not self.injector.initialize(iface):
            raise NameError("Failed to initialize injector")

        return True

    def startCallback(self):
        self.iface_monitor = InterfaceMonitor(self.iface.get('iface'),
                                              self.handle_packet_external)
        self.iface_monitor.start()

        self.loopback_monitor = InterfaceMonitor(self.LOOPBACK_IFACE,
                                                 self.handle_packet_internal)
        self.loopback_monitor.start()

        if not self._save_config():
            self.logger.error('Failed to save config')
            return False

        if not self._change_config():
            self.logger.error('Failed to change config')
            return False

        self.is_running = True
        self.logger.info('%s is running' % (self.__class__.__name__))
        return True

    def stopCallback(self):
        self.is_running = False
        if self.iface_monitor is not None:
            self.iface_monitor.stop()
        if self.loopback_monitor is not None:
            self.loopback_monitor.stop()
        self._restore_config()
        return True

    #--------------------------------------------------------------
    # main packet handler callback
    #--------------------------------------------------------------
    def handle_packet_external(self, pctx):
        if self._is_my_ip_public(pctx.ip_packet.src):
            return

        if not self._is_in_inject_cache(pctx):
            return


        cb3 = []
        cb4 = [
            self._darwin_fix_ip_external,
        ]
        ipkt = pctx.ip_packet
        self.handle_pkt(pctx, cb3, cb4)
        self.handle_inject(pctx)
        return

    def handle_packet_internal(self, pctx):
        '''
        Main callback to handle a packet
        @param pctx: DarwinPacketCtx object created for each packet
        @return True on success False on error
        @NOTE: pctx gets updated as it traverse through this callback
               Check pctx.mangled flag to see if the packet has been
               mangled
        '''

        cb3 = [
            self.check_log_icmp,
            self._darwin_fix_ip_icmp,
        ]
        cb4 = [
            self.maybe_redir_port,
            self._darwin_fix_ip_internal,
            self.maybe_fixup_sport,
        ]
        self.handle_pkt(pctx, cb3, cb4)
        self.handle_inject(pctx)
        return

    def update_inject_cache(self, pctx):
        endpoint = fnpacket.PacketCtx.gen_endpoint_key(
            pctx.protocol, pctx.src_ip, pctx.sport)
        self.inject_cache[endpoint] = True
        return True

    def select_injector(self, ip):
        if ip == LOOPBACK_IP:
            return self.loopback_injector

        if ip == self.loopback_ip or ip == self.loopback_ip_fake:
            return self.loopback_injector

        return self.injector

    def handle_inject(self, pctx):
        if not pctx.to_inject:
            return False

        bytez = self.make_bytez(pctx)
        if bytez is None:
            self.logger.error('Failed to make bytez from pkt_ctx')
            return False

        self.update_inject_cache(pctx)

        injector = self.select_injector(pctx.dst_ip)
        injector.inject(bytez)
        return True

    def make_bytez(self, pctx):
        ipkt = pctx.ip_packet
        if pctx.protocol == 'TCP':
            otport = ipkt[TCP]
            pload = TCP(
                sport=pctx.sport, dport=pctx.dport,
                seq=otport.seq, ack=otport.ack, dataofs=otport.dataofs,
                window=otport.window, flags=otport.flags, options=otport.options
            )/otport.payload
        elif pctx.protocol == 'UDP':
            otport = ipkt[UDP]
            pload = UDP(sport=pctx.sport, dport=pctx.dport)/otport.payload
        else:
            pload = ipkt.payload

        bytez = IP(src=pctx.src_ip, dst=pctx.dst_ip)/pload
        return bytez

    #--------------------------------------------------------------
    # implements various DarwinUtilsMixin methods
    #--------------------------------------------------------------
    def getNewDestination(self, ip):
        if self._is_my_ip_loopback(ip):
            return self.loopback_ip
        return self.loopback_ip_fake

    def getLoopbackDestination(self):
        return self.loopback_ip

    def check_should_ignore(self, pkt, pid, comm):
        if super(UsermodeDiverter, self).check_should_ignore(pkt, pid, comm):
            pkt.to_inject = False
            return True

        if pkt.src_ip == self.loopback_ip and pkt.dst_ip == self.loopback_ip_fake:
            pkt.to_inject = False
            return True

        if pkt.src_ip == self.loopback_ip:
            return False
        if pkt.src_ip == self.loopback_ip_fake:
            return False

        pkt.to_inject = False
        return True

    def _darwin_fix_ip_icmp(self, crit, pkt):
        if not pkt.is_icmp:
            return

        newdst = self.getNewDestination(pkt.src_ip)
        pkt.src_ip, pkt.dst_ip = pkt.dst_ip, pkt.src_ip
        pkt.dst_ip = newdst
        return

    def _darwin_fix_ip_external(self, crit, pkt, pid, comm):
        newdst = self.getLoopbackDestination()
        pkt.dst_ip = newdst
        pkt.to_inject = True
        return

    def _darwin_fix_ip_internal(self, crit, pkt, pid, comm):
        '''
        Check if we should redirect this packet to local listener
        '''
        if self.check_should_ignore(pkt, pid, comm):
            pkt.src_ip = self.iface.get('addr.inet')[0]
            return True

        # always assume that we are in single host mode
        # hacky: swap src/dst before changing
        newdst = self.getNewDestination(pkt.src_ip)
        pkt.src_ip, pkt.dst_ip = pkt.dst_ip, pkt.src_ip
        pkt.dst_ip = newdst
        return

    def decide_redir_port(self, pkt, bound_ports):
        '''
        @override port ridirection logic
        '''
        # referencing the original packets, not the pctx that may have been
        # mangled by upper layer callbacks

        a = src_local = self._is_my_ip(pkt.src_ip0)
        c = sport_bound = pkt.sport in (bound_ports)
        d = dport_bound = pkt.dport in (bound_ports)
        rc = (not a and not d) or (not c and not d)
        return rc


    def maybe_redir_port(self, crit, pkt, pid, comm):
        '''
        @override
        '''

        if pid == self.pid:
            self.logger.info("Ignoring traffic from self")
            return

        default =  self.default_listener.get(pkt.proto, None)
        if default is None:
            self.logger.error("There is no default listener")
            return

        with self.port_fwd_table_lock:
            if pkt.dkey in self.port_fwd_table:
                return

        dport_hidden_listener = crit.dport_hidden_listener
        bound_ports = self.listener_ports.getPortList(pkt.proto)
        if dport_hidden_listener or self.decide_redir_port(pkt, bound_ports):
            self.pdebug(DDPFV, 'Condition 2 satisfied: Packet destined for '
                        'unbound port or hidden listener')

            with self.ignore_table_lock:
                if ((pkt.dkey in self.ignore_table) and
                        (self.ignore_table[pkt.dkey] == pkt.sport)):
                    return

            self.pdebug(DDPFV, ' + ADDING portfwd key entry: ' + pkt.skey)
            with self.port_fwd_table_lock:
                self.logger.error("Adding %s:%s into table" %
                    (pkt.skey, pkt.dport))
                self.port_fwd_table[pkt.skey] = pkt.dport

            self.pdebug(DDPF, 'Redirecting %s to go to port %d' %
                        (pkt.hdrToStr(), default))
            pkt.dport = default
        else:
            self.delete_stale_port_fwd_key(pkt.skey)

        if crit.first_packet_new_session:
            self.addSession(pkt)

            # Execute command if applicable
            self.maybeExecuteCmd(pkt, pid, comm)
        return


    def maybe_fixup_sport(self, crit, pkt, pid, comm):
        '''
        @override
        '''
        key = pkt.get_current_dkey()
        with self.port_fwd_table_lock:
            new_sport = self.port_fwd_table.get(key)

        if new_sport is not None:
            pkt.sport = new_sport

        return


    #--------------------------------------------------------------
    # implements various DirverterPerOSDelegate() abstract methods
    #--------------------------------------------------------------

    def get_pid_comm(self, pkt):
        '''
        Given a packet, return pid and command/process name that generates the
        packet.
        @param pkt: DarwinPacketCtx
        @return None, None if errors
        '''
        return self._get_pid_comm(pkt)



    # -----------------------------------------------------------------
    # Internal methods, do not call!
    # -----------------------------------------------------------------
    def _change_config(self):
        '''
        Apply the following network configuration changese:
        - Add an IP alias to the loopback interface.
        - Change the default gateway to the newly alias IP.
        - Enable forwarding if it is currently disabled.
        @return True on sucess, False on failure.
        '''
        if len(self.configs) <= 0:
            if not self._save_config():
                self.logger.error('Save config failed')
                return False
        if not self._add_loopback_alias():
            self.logger.error('Failed to add loopback alias')
            return False
        if not self._change_default_route():
            self.logger.error('Failed to change default route')
            return False
        if not self._change_dns_server():
            self.logger.error('Failed to set dns server')
            return False
        return True


    def _save_config(self):
        '''
        Save the following network configuration:
        - net.inet.ip.forwarding
        - Current default gateway
        @return True on sucess, False on failure.
        '''
        configs = dict()
        try:
            ifs = sp.check_output('sysctl net.inet.ip.forwarding',
                                  shell=True, stderr=self.devnull)
            _,v = ifs.strip().split(':', 2)
            v = int(v, 10)
        except:
            self.logger.error('Save config failed')
            return False
        configs['net.forwarding'] = v

        try:
            iface, ipaddr, gw = conf.route.route('0.0.0.0')
        except:
            return False

        configs['net.iface'] = iface
        configs['net.ipaddr'] = ipaddr
        configs['net.gateway'] = gw
        configs['net.dns'] = gw
        self.configs = configs
        return True

    def _add_loopback_alias(self):
        '''Try to execute all commands. Only return success if all commands are
        executed successfully
        '''
        cmds = [
            'ifconfig lo0 alias %s' % (self.loopback_ip,),
            'ifconfig lo0 alias %s' % (self.loopback_ip_fake,),
        ]
        for cmd in cmds:
            if not self._quiet_call(cmd):
                return False
        return True

    def _change_default_route(self):
        '''
        Try to change the default route. If that fails, add a default route
        to the specified IP address
        '''
        cmds = [
            'route -n change default %s' % (self.loopback_ip,),
            'route -n add default %s' % (self.loopback_ip,),
        ]
        for cmd in cmds:
            if self._quiet_call(cmd):
                return True
        return False

    def _change_dns_server(self):
        cmd = 'networksetup -setdnsservers Ethernet 127.0.0.1'
        if self._quiet_call(cmd):
            return True
        return False

    def _restore_config(self):
        '''
        Restore the following network settings. This should always
        return True
        - Default route
        - Remove loopback IP aliases
        @return True on sucess, False on failure.
        '''
        if len(self.configs) == 0:
            return True
        self._fix_default_route()
        self._remove_loopback_alias()
        self._fix_dns_server()
        return True

    def _fix_dns_server(self):
        dns = self.configs.get('net.dns')
        cmd = 'networksetup -setdnsservers Ethernet %s' % (dns,)
        if not self._quiet_call(cmd):
            return False
        return True

    def _remove_loopback_alias(self):
        cmds = [
            'ifconfig lo0 -alias %s' % (self.loopback_ip,),
            'ifconfig lo0 -alias %s' % (self.loopback_ip_fake,)
        ]
        for cmd in cmds:
            if not self._quiet_call(cmd):
                return False
        return True

    def _fix_default_route(self):
        gw = self.configs.get('net.gateway', None)
        if gw is None:
            return self._quiet_call('route -n delete default')
        return self._quiet_call('route -n change default %s'% (gw,))


    def _quiet_call(self, cmd):
        '''
        Simple wrapper to execute shell command quietly
        @attention: Is shell=True a security concern?
        '''
        try:
            sp.check_call(cmd,
                          stdout=self.devnull,
                          stderr=sp.STDOUT,
                          shell=True)
        except:
            self.logger.error('Failed to run: %s' % (cmd,))
            stk = traceback.format_exc()
            self.logger.debug(">>> Stack:\n%s" % (stk,))
            return False
        return True\

    def _get_pid_comm(self, ipkt):
        if not ipkt.protocol == 'TCP' and not ipkt.protocol == 'UDP':
            return None, None

        protospec = "-i%s%s@%s" % (
            ipkt.ip_packet.version, ipkt.protocol, ipkt.dst_ip)

        if ipkt.dport:
            protospec = "%s:%s" % (protospec, ipkt.dport)
        cmd = [
            'lsof', '-wnPF', 'cLn',
            protospec
        ]
        with open('lsof.txt', 'a+') as ofile:
            ofile.write("%s\n" % (protospec,))

        try:
            result = sp.check_output(cmd, stderr=None).strip()
        except:
            result = None
        if result is None:
            return None, None

        lines = result.split('\n')
        for record in self._generate_records(lines):
            _result = self._parse_record(record)
            if _result is None:
                continue
            if self._is_my_packet(_result):
                return _result.get('pid'), _result.get('comm')

        return None, None

    def _generate_records(self, lines):
        n = len(lines)
        maxlen = (n // 5) * 5
        lines = lines[:maxlen]
        for i in xrange(0, len(lines), 5):
            try:
                record = lines[i:i+5]
                pid = record[0][1:]
                comm = record[1][1:]
                uname = record[2][1:]
                name = record[4][1:]
                yield {'pid': pid, 'comm': comm, 'name': name, 'uname': uname}
            except IndexError:
                yield {}

    def _parse_record(self, record):
        name = record.get('name')
        if name is None:
            return None

        try:
                src_endpoint, dst_endpoint = name.split('->')
                src, sport = src_endpoint.split(':')
                dst, dport = dst_endpoint.split(':')
        except:
            return None

        record.update({'src': src, 'dst': dst, 'sport': sport, 'dport': dport})
        try:
            record['pid'] = int(record.get('pid'))
        except:
            record['pid'] = ''
        return record

    def _is_my_packet(self, record):
        src, dst = record.get('src'), record.get('dst')
        if src == self.loopback_ip or src == self.loopback_ip_fake:
            return True

        if dst == self.loopback_ip or dst == self.loopback_ip_fake:
            return True

        return False

    def _is_my_ip_loopback(self, ip):
        if ip == self.loopback_ip or ip == self.loopback_ip_fake:
            return True
        return False

    def _is_my_ip_public(self, ip):
        try:
            rc = ip == self.iface.get('addr.inet')[0]
        except:
            rc = False
        return rc

    def _is_in_inject_cache(self, pctx):
        endpoint = fnpacket.PacketCtx.gen_endpoint_key(
            pctx.protocol, pctx.dst_ip, pctx.dport)
        return endpoint in self.inject_cache

    def _is_my_ip(self, ip):
        if ip == self.loopback_ip or ip == self.loopback_ip_fake:
            return True

        if ip == LOOPBACK_IP:
            return True

        return False
