import sys
import dpkt
import time
import socket
import logging
import threading
import subprocess
import diverterbase
import netfilterqueue
from linutil import *
from diverterbase import *
from collections import namedtuple
from netfilterqueue import NetfilterQueue


class PacketHandler:
    """Used to encapsulate common patterns in packet hooks."""

    def __init__(self, pkt, diverter, label, callbacks3, callbacks4):
        self.logger = logging.getLogger('Diverter')

        self.pkt = pkt
        self.diverter = diverter  # Relies on Diverter for certain operations
        self.label = label
        self.callbacks3 = callbacks3
        self.callbacks4 = callbacks4

        self.raw = self.pkt.get_payload()
        self.ipver = ((ord(self.raw[0]) & 0xf0) >> 4)
        self.hdr, self.proto = self.diverter.parse_pkt[self.ipver](self.ipver,
                                                                   self.raw)

    def handle_pkt(self):
        """Generic packet hook.

        1.) Common prologue:
            A.) Unconditionally Write unmangled packet to pcap
            B.) Parse IP packet

        2.) Call layer 3 (network) callbacks...

        3.) Parse higher-layer protocol (TCP, UDP) for port numbers

        4.) Call layer 4 (transport) callbacks...

        5.) Common epilogue:
            A.) If the packet headers have been modified:
                i.) Double-write the mangled packet to the pcap for SSL
                    decoding purposes
                ii.) Update the packet payload with NetfilterQueue
            B.) Accept the packet with NetfilterQueue
        """

        # 1A: Unconditionally write unmangled packet to pcap
        self.diverter.write_pcap(self.hdr.pack())

        if (self.hdr, self.proto) == (None, None):
            self.logger.warning('%s: Failed to parse IP packet' % (self.label))
        else:
            proto_name = self.diverter.handled_protocols.get(self.proto)

            self.diverter.pdebug(DGENPKT, '%s %s' % (self.label,
                                 self.diverter.hdr_to_str(proto_name,
                                 self.hdr)))

            # 1B: Parse IP packet (actually done in ctor)
            self.src_ip = socket.inet_ntoa(self.hdr.src)
            self.dst_ip = socket.inet_ntoa(self.hdr.dst)

            # 2: Call layer 3 (network) callbacks
            for cb in self.callbacks3:
                # These debug outputs are useful for figuring out which
                # callback is responsible for an exception that was masked by
                # python-netfilterqueue's global callback.
                self.diverter.pdebug(DCB, 'Calling %s' % (cb))

                cb(self.label, self.hdr, self.ipver, self.proto, proto_name,
                   self.src_ip, self.dst_ip)

                self.diverter.pdebug(DCB, '%s finished' % (cb))

            if proto_name:

                if len(self.callbacks4):
                    # 3: Parse higher-layer protocol
                    self.sport = self.hdr.data.sport
                    self.dport = self.hdr.data.dport
                    self.skey = self.diverter.gen_endpoint_key(proto_name,
                                                               self.src_ip,
                                                               self.sport)
                    self.dkey = self.diverter.gen_endpoint_key(proto_name,
                                                               self.dst_ip,
                                                               self.dport)

                    pid, comm = self.diverter.linux_get_pid_comm_by_endpoint(
                        self.ipver, proto_name, self.src_ip, self.sport)

                    if proto_name == 'UDP':
                        fmt = '| {label} {proto} | {pid:>6} | {comm:<8} | {src:>15}:{sport:<5} | {dst:>15}:{dport:<5} | {length:>5} | {flags:<11} | {seqack:<35} |'
                        logline = fmt.format(
                                label=self.label,
                                proto=proto_name,
                                pid=pid,
                                comm=comm,
                                src=self.src_ip,
                                sport=self.sport,
                                dst=self.dst_ip,
                                dport=self.dport,
                                length=len(self.raw),
                                flags='',
                                seqack='',
                            )
                        self.diverter.pdebug(DGENPKTV, logline)

                    elif proto_name == 'TCP':
                        tcp = self.hdr.data
                        # Interested in:
                        # SYN
                        # SYN,ACK
                        # ACK
                        # PSH
                        # FIN
                        syn = (tcp.flags & dpkt.tcp.TH_SYN) != 0
                        ack = (tcp.flags & dpkt.tcp.TH_ACK) != 0
                        fin = (tcp.flags & dpkt.tcp.TH_FIN) != 0
                        psh = (tcp.flags & dpkt.tcp.TH_PUSH) != 0
                        rst = (tcp.flags & dpkt.tcp.TH_RST) != 0

                        sa = 'Seq=%d, Ack=%d' % (tcp.seq, tcp.ack)
                        f = []
                        if rst:
                            f.append('RST')
                        if syn:
                            f.append('SYN')
                        if ack:
                            f.append('ACK')
                        if fin:
                            f.append('FIN')
                        if psh:
                            f.append('PSH')

                        fmt = '| {label} {proto} | {pid:>6} | {comm:<8} | {src:>15}:{sport:<5} | {dst:>15}:{dport:<5} | {length:>5} | {flags:<11} | {seqack:<35} |'
                        logline = fmt.format(
                                label=self.label,
                                proto=proto_name,
                                pid=pid,
                                comm=comm,
                                src=self.src_ip,
                                sport=self.sport,
                                dst=self.dst_ip,
                                dport=self.dport,
                                length=len(self.raw),
                                flags=','.join(f),
                                seqack=sa,
                            )
                        self.diverter.pdebug(DGENPKTV, logline)

                    if ((not (self.diverter.pdebug_level & DGENPKTV)) and
                        pid and (pid != self.diverter.pid)):
                        self.logger.info('  pid:  %d name: %s' %
                                         (pid, comm if comm else 'Unknown'))

                    hdr_latest = self.hdr
                    modified = False

                    # 4: Layer 4 (Transport layer) callbacks
                    for cb in self.callbacks4:
                        # These debug outputs are useful for figuring out which
                        # callback is responsible for an exception that was
                        # masked by python-netfilterqueue's global callback.
                        self.diverter.pdebug(DCB, 'Calling %s' % (cb))

                        hdr_mod = cb(self.label, pid, comm, self.ipver,
                                     hdr_latest, proto_name,
                                     self.src_ip, self.sport, self.skey,
                                     self.dst_ip, self.dport, self.dkey)

                        if hdr_mod:
                            hdr_latest = hdr_mod
                            modified = True

                        self.diverter.pdebug(DCB, '%s finished' % (cb))

                    if modified:
                        # 5Ai: Double write mangled packets to represent changes
                        # made by FakeNet-NG while still allowing SSL decoding
                        self.diverter.write_pcap(hdr_latest.pack())

                        # 5Aii: Finalize changes with nfq
                        self.pkt.set_payload(hdr_latest.pack())
            else:
                self.diverter.pdebug(DGENPKT, '%s: Not handling protocol %s' %
                                     (self.label, self.proto))

        # 5B: NF_ACCEPT
        self.pkt.accept()


class Diverter(DiverterBase, LinUtilMixin):
    def __init__(self, diverter_config, listeners_config, ip_addrs,
                 logging_level=logging.INFO):
        self.init_base(diverter_config, listeners_config, ip_addrs,
                       logging_level)

        self.init_linux_mixin()
        self.init_diverter_linux()

    def init_diverter_linux(self):
        """Linux-specific Diverter initialization."""
        # String list configuration item that is specific to the Linux
        # Diverter, will not be parsed by DiverterBase, and needs to be
        # accessed as an array in the future.
        slists = ['linuxredirectnonlocal', 'DebugLevel']
        self.reconfigure(portlists=[], stringlists=slists)

        dbg_lvl = 0
        if self.is_configured('DebugLevel'):
            for label in self.getconfigval('DebugLevel'):
                label = label.upper()
                if label == 'OFF':
                    dbg_lvl = 0
                    break
                if not label in DLABELS_INV:
                    self.logger.warning('No such DebugLevel as %s' % (label))
                else:
                    dbg_lvl |= DLABELS_INV[label]
        self.set_debug_level(dbg_lvl, DLABELS)

        # SingleHost vs MultiHost mode
        mode = 'SingleHost'  # Default
        self.single_host_mode = True
        if self.is_configured('networkmode'):
            mode = self.getconfigval('networkmode')
            available_modes = ['singlehost', 'multihost']

            # Constrain argument values
            if mode.lower() not in available_modes:
                self.logger.error('NetworkMode must be one of %s' %
                                  (available_modes))
                sys.exit(1)

            # Adjust previously assumed mode if user specifies MultiHost
            if mode.lower() == 'multihost':
                self.single_host_mode = False

        if self.single_host_mode:
            while True:
                prompt = ('You acknowledge that SingleHost mode on Linux is ' +
                          'experimental and not functionally complete? ' +
                          '[Y/N] ')
                acknowledgement = raw_input(prompt)
                okay = ['y', 'yes', 'yeah', 'sure', 'okay', 'whatever']
                nope = ['n', 'no', 'nah', 'nope']
                if acknowledgement.lower() in okay:
                    self.logger.info('Okay, we\'ll take it for a spin!')
                    break
                elif acknowledgement.lower() in nope:
                    self.logger.error('User opted out of crowd-sourced ' +
                                      'alpha testing program ;-)')
                    sys.exit(1)

        self.logger.info('Running in %s mode' % (mode))

        self.parse_pkt = dict()
        self.parse_pkt[4] = self.parse_ipv4
        self.parse_pkt[6] = self.parse_ipv6

        self.nfqueues = list()

        self.handled_protocols = {
            dpkt.ip.IP_PROTO_TCP: 'TCP',
            dpkt.ip.IP_PROTO_UDP: 'UDP',
        }

        # Track iptables rules not associated with any nfqueue object
        self.rules_added = []

        # Manage logging of foreign-destined packets
        self.nonlocal_ips_already_seen = []
        self.log_nonlocal_only_once = True

        # Port forwarding table, for looking up original unbound service ports
        # when sending replies to foreign endpoints that have attempted to
        # communicate with unbound ports. Allows fixing up source ports in
        # response packets. Similar to the `sessions` member of the Windows
        # Diverter implementation.
        self.port_fwd_table = dict()
        self.port_fwd_table_lock = threading.Lock()

        # Track conversations that will be ignored so that e.g. an RST response
        # from a closed port does not erroneously trigger port forwarding and
        # silence later replies to legitimate clients.
        self.ignore_table = dict()
        self.ignore_table_lock = threading.Lock()

        # IP forwarding table, for looking up original foreign destination IPs
        # when sending replies to local endpoints that have attempted to
        # communicate with other machines e.g. via hard-coded C2 IP addresses.
        self.ip_fwd_table = dict()
        self.ip_fwd_table_lock = threading.Lock()

        # NOTE: Constraining cache size via LRU or similar is a non-requirement
        # due to the short anticipated runtime of FakeNet-NG. If you see your
        # FakeNet-NG consuming large amounts of memory, contact your doctor to
        # find out if Ctrl+C is right for you.

        # The below callbacks are configured to be efficiently executed by a
        # PacketHandler object within the nonlocal, incoming, and outgoing
        # packet hooks installed by the start method.

        # Network layer callbacks for nonlocal-destined packets
        #
        # Log nonlocal-destined packets and ICMP packets before they are NATted
        # to localhost
        self.nonlocal_net_cbs = [self.check_log_nonlocal, self.check_log_icmp]

        # Network and transport layer callbacks for incoming packets
        #
        # IP redirection fix-ups are only for SingleHost mode.
        self.incoming_net_cbs = []
        self.incoming_trans_cbs = [self.maybe_redir_port]
        if self.single_host_mode:
            self.incoming_trans_cbs.append(self.maybe_fixup_srcip)

        # Network and transport layer callbacks for outgoing packets.
        #
        # Must scan for nonlocal packets in the output hook and at the network
        # layer (regardless of whether supported protocols like TCP/UDP can be
        # parsed) when using the SingleHost mode of FakeNet-NG. Note that if
        # this check were performed when FakeNet-NG is operating in MultiHost
        # mode, every response packet generated by a listener and destined for
        # a remote host would erroneously be sent for potential logging as
        # nonlocal host communication. ICMP logging is performed for outgoing
        # packets in SingleHost mode because this will allow logging of the
        # original destination IP address before it was mangled to redirect the
        # packet to localhost.
        self.outgoing_net_cbs = []
        if self.single_host_mode:
            self.outgoing_net_cbs.append(self.check_log_nonlocal)
            self.outgoing_net_cbs.append(self.check_log_icmp)

        self.outgoing_trans_cbs = [self.maybe_fixup_sport]

        # IP redirection is only for SingleHost mode
        if self.single_host_mode:
            self.outgoing_trans_cbs.append(self.maybe_redir_ip)

    def start(self):
        self.logger.info('Starting Linux Diverter...')

        if not self.check_privileged():
            self.logger.error('The Linux Diverter requires administrative ' +
                              'privileges')
            sys.exit(1)

        ret = self.linux_capture_iptables()
        if ret != 0:
            sys.exit(1)

        if self.is_set('linuxflushiptables'):
            self.linux_flush_iptables()
        else:
            self.logger.warning('LinuxFlushIptables is disabled, this may ' +
                                'result in unanticipated behavior depending ' +
                                'upon what rules are already present')

        hookspec = namedtuple('hookspec', ['chain', 'table', 'callback'])

        callbacks = list()

        # If you are considering adding or moving hooks that mangle packets,
        # see the section of docs/internals.md titled Explaining Hook Location
        # Choices for an explanation of how to avoid breaking the Linux NAT
        # implementation.
        if not self.single_host_mode:
            callbacks.append(hookspec('PREROUTING', 'raw',
                                      self.handle_nonlocal))

        callbacks.append(hookspec('INPUT', 'mangle', self.handle_incoming))
        callbacks.append(hookspec('OUTPUT', 'raw', self.handle_outgoing))

        nhooks = len(callbacks)

        self.pdebug(DNFQUEUE, ('Discovering the next %d available NFQUEUE ' +
                    'numbers') % (nhooks))
        qnos = self.linux_get_next_nfqueue_numbers(nhooks)
        if len(qnos) != nhooks:
            self.logger.error('Could not procure a sufficient number of ' +
                              'netfilter queue numbers')
            sys.exit(1)

        self.pdebug(DNFQUEUE, 'Next available NFQUEUE numbers: ' + str(qnos))

        self.pdebug(DNFQUEUE, 'Enumerating queue numbers and hook ' +
                    'specifications to create NFQUEUE objects')
        self.nfqueues = list()
        for qno, hk in zip(qnos, callbacks):
            self.pdebug(DNFQUEUE, ('Creating NFQUEUE object for chain %s / ' +
                        'table %s / queue # %d => %s') % (hk.chain, hk.table,
                        qno, str(hk.callback)))
            q = LinuxDiverterNfqueue(qno, hk.chain, hk.table, hk.callback)
            self.nfqueues.append(q)
            ok = q.start()
            if not ok:
                self.logger.error('Failed to start NFQUEUE for %s' % (str(q)))
                self.stop()
                sys.exit(1)

        if self.single_host_mode and self.is_set('fixgateway'):
            if not self.linux_get_default_gw():
                self.linux_set_default_gw()

        if self.single_host_mode and self.is_set('modifylocaldns'):
            self.linux_modifylocaldns_ephemeral()

        if self.is_configured('linuxflushdnscommand'):
            cmd = self.getconfigval('linuxflushdnscommand')
            ret = subprocess.call(cmd.split())
            if ret != 0:
                self.logger.error('Failed to flush DNS cache.')

        if self.is_configured('linuxredirectnonlocal'):
            self.pdebug(DMISC, 'Processing LinuxRedirectNonlocal')
            specified_ifaces = self.getconfigval('linuxredirectnonlocal')
            self.pdebug(DMISC, 'Processing linuxredirectnonlocal on ' +
                        'interfaces: %s' % (specified_ifaces))
            ok, rules = self.linux_iptables_redir_nonlocal(specified_ifaces)

            # Irrespective of whether this failed, we want to add any
            # successful iptables rules to the list so that stop() will be able
            # to remove them using linux_remove_iptables_rules().
            self.rules_added += rules

            if not ok:
                self.logger.error('Failed to process LinuxRedirectNonlocal')
                self.stop()
                sys.exit(1)

        ok, rule = self.linux_redir_icmp()
        if not ok:
            self.logger.error('Failed to redirect ICMP')
            self.stop()
            sys.exit(1)

        self.rules_added.append(rule)

    def stop(self):
        self.logger.info('Stopping Linux Diverter...')

        self.pdebug(DNFQUEUE, 'Notifying NFQUEUE objects of imminent stop')
        for q in self.nfqueues:
            q.stop_nonblocking()

        self.pdebug(DIPTBLS, 'Removing iptables rules not associated with any ' +
                    'NFQUEUE object')
        self.linux_remove_iptables_rules(self.rules_added)

        for q in self.nfqueues:
            self.pdebug(DNFQUEUE, 'Stopping NFQUEUE for %s' % (str(q)))
            q.stop()

        if self.pcap:
            self.pdebug(DMISC, 'Closing pcap file %s' % (self.pcap_filename))
            self.pcap.close()  # Only after all queues are stopped

        self.logger.info('Stopped Linux Diverter')

        if self.single_host_mode and self.is_set('modifylocaldns'):
            self.linux_restore_local_dns()

        self.linux_restore_iptables()

    def handle_nonlocal(self, pkt):
        """Handle comms sent to IP addresses that are not bound to any adapter.

        This allows analysts to observe when malware is communicating with
        hard-coded IP addresses in MultiHost mode.
        """
        h = PacketHandler(pkt, self, 'handle_nonlocal', self.nonlocal_net_cbs,
                [])
        h.handle_pkt()

    def handle_incoming(self, pkt):
        """Incoming packet hook.

        Specific to incoming packets:
        5.) If SingleHost mode:
            a.) Conditionally fix up source IPs to support IP forwarding for
                otherwise foreign-destined packets
        4.) Conditionally mangle destination ports to implement port forwarding
            for unbound ports to point to the default listener

        No return value.
        """
        h = PacketHandler(pkt, self, 'handle_incoming', self.incoming_net_cbs,
                self.incoming_trans_cbs)
        h.handle_pkt()

    def handle_outgoing(self, pkt):
        """Outgoing packet hook.

        Specific to outgoing packets:
        4.) If SingleHost mode:
            a.) Conditionally log packets destined for foreign IP addresses
                (the corresponding check for MultiHost mode is called by
                handle_nonlocal())
            b.) Conditionally mangle destination IPs for otherwise foreign-
                destined packets to implement IP forwarding
        5.) Conditionally fix up mangled source ports to support port
            forwarding

        No return value.
        """
        h = PacketHandler(pkt, self, 'handle_outgoing', self.outgoing_net_cbs,
                self.outgoing_trans_cbs)
        h.handle_pkt()

    def parse_ipv4(self, ipver, raw):
        hdr = dpkt.ip.IP(raw)
        if hdr.hl < 5:
            return (None, None)  # An IP header length less than 5 is invalid
        return hdr, hdr.p

    def parse_ipv6(self, ipver, raw):
        hdr = dpkt.ip6.IP6(raw)
        return hdr, hdr.nxt

    def gen_endpoint_key(self, proto_name, ip, port):
        """e.g. 192.168.19.132:tcp/3030"""
        return str(ip) + ':' + str(proto_name) + '/' + str(port)

    def check_log_icmp(self, label, hdr, ipver, proto, proto_name, src_ip,
                       dst_ip):
        if proto == dpkt.ip.IP_PROTO_ICMP:
            self.logger.info('ICMP type %d code %d %s' % (
                hdr.data.type, hdr.data.code, self.hdr_to_str(None, hdr)))

        return None

    def check_log_nonlocal(self, label, hdr, ipver, proto, proto_name, src_ip,
                           dst_ip):
        if dst_ip not in self.ip_addrs[ipver]:
            self._maybe_log_nonlocal(hdr, ipver, proto, dst_ip)

        return None

    def _maybe_log_nonlocal(self, hdr, ipver, proto, dst_ip):
        """Conditionally log packets having a foreign destination.

        Each foreign destination will be logged only once if the Linux
        Diverter's internal log_nonlocal_only_once flag is set. Otherwise, any
        foreign destination IP address will be logged each time it is observed.
        """
        proto_name = self.handled_protocols.get(proto)

        self.pdebug(DNONLOC, 'Nonlocal %s' %
                    (self.hdr_to_str(proto_name, hdr)))

        first_sighting = (dst_ip not in self.nonlocal_ips_already_seen)

        if first_sighting:
            self.nonlocal_ips_already_seen.append(dst_ip)

        # Log when a new IP is observed OR if we are not restricted to
        # logging only the first occurrence of a given nonlocal IP.
        if first_sighting or (not self.log_nonlocal_only_once):
            self.logger.info(
                'Received nonlocal IPv%d datagram destined for %s' %
                (ipver, dst_ip))

    def check_should_ignore(self, pid, comm, ipver, hdr, proto_name, src_ip,
                            sport, dst_ip, dport):
        # SingleHost mode checks
        if self.single_host_mode:
            if comm:
                if comm in self.blacklist_processes:
                    self.pdebug(DIGN, ('Ignoring %s packet from process %s ' +
                                'in the process blacklist.') % (proto_name,
                                comm))
                    self.pdebug(DIGN, '  %s' %
                                (self.hdr_to_str(proto_name, hdr)))
                    return True

                elif (len(self.whitelist_processes) and (comm not in
                      self.whitelist_processes)):
                    self.pdebug(DIGN, ('Ignoring %s packet from process %s ' +
                                'not in the process whitelist.') % (proto_name,
                                comm))
                    self.pdebug(DIGN, '  %s' %
                                (self.hdr_to_str(proto_name, hdr)))
                    return True

                # Check per-listener blacklisted process list
                elif ((proto_name in self.port_process_blacklist) and
                        (dport in self.port_process_blacklist[proto_name])):
                    # If program DOES match blacklist
                    if comm in self.port_process_blacklist[proto_name][dport]:
                        self.pdebug(DIGN, ('Ignoring %s request packet from ' +
                                    'process %s in the listener process ' +
                                    'blacklist.') % (proto_name, comm))
                        self.pdebug(DIGN, '  %s' %
                                    (self.hdr_to_str(proto_name, hdr)))

                    return True

                # Check per-listener whitelisted process list
                elif ((proto_name in self.port_process_whitelist) and
                        (dport in self.port_process_whitelist[proto_name])):
                    # If program does NOT match whitelist
                    if not comm in self.port_process_whitelist[proto_name][dport]:
                        self.pdebug(DIGN, ('Ignoring %s request packet from ' +
                                    'process %s not in the listener process ' +
                                    'whitelist.') % (proto_name, comm))
                        self.pdebug(DIGN, '  %s' %
                                    (self.hdr_to_str(proto_name, hdr)))
                        return True

        # MultiHost mode checks
        else:
            pass  # None as of yet

        # Checks independent of mode

        if set(self.blacklist_ports[proto_name]).intersection([sport, dport]):
            self.pdebug(DIGN, 'Forwarding blacklisted port %s packet:' %
                        (proto_name))
            self.pdebug(DIGN, '  %s' % (self.hdr_to_str(proto_name, hdr)))
            return True

        global_host_blacklist = self.getconfigval('hostblacklist')
        if global_host_blacklist and dst_ip in global_host_blacklist:
            self.pdebug(DIGN, ('Ignoring %s packet to %s in the host ' +
                        'blacklist.') % (proto_name, dst_ip))
            self.pdebug(DIGN, '  %s' % (self.hdr_to_str(proto_name, hdr)))
            return True

        if ((proto_name in self.port_host_whitelist) and
                (dport in self.port_host_whitelist[proto_name])):
            # If host does NOT match whitelist
            if not dst_ip in self.port_host_whitelist[proto_name][dport]:
                self.pdebug(DIGN, ('Ignoring %s request packet to %s not in ' +
                            'the listener host whitelist.') % (proto_name,
                            dst_ip))
                self.pdebug(DIGN, '  %s' % (self.hdr_to_str(proto_name, hdr)))
                return True

        if ((proto_name in self.port_host_blacklist) and
                (dport in self.port_host_blacklist[proto_name])):
            # If host DOES match blacklist
            if dst_ip in self.port_host_blacklist[proto_name][dport]:
                self.pdebug(DIGN, ('Ignoring %s request packet to %s in the ' +
                            'listener host blacklist.') % (proto_name, dst_ip))
                self.pdebug(DIGN, '  %s' % (self.hdr_to_str(proto_name, hdr)))
                return True

        # Duplicated from diverters/windows.py:
        # HACK: FTP Passive Mode Handling
        # Check if a listener is initiating a new connection from a
        # non-diverted port and add it to blacklist. This is done to handle a
        # special use-case of FTP ACTIVE mode where FTP server is initiating a
        # new connection for which the response may be redirected to a default
        # listener.  NOTE: Additional testing can be performed to check if this
        # is actually a SYN packet
        if pid == self.pid:
            if (
                ((dst_ip in self.ip_addrs[ipver]) and
                (not dst_ip.startswith('127.'))) and
                ((src_ip in self.ip_addrs[ipver]) and
                (not dst_ip.startswith('127.'))) and
                (not set([sport, dport]).intersection(self.diverted_ports[proto_name]))
                ):

                self.pdebug(DIGN | DFTP, 'Listener initiated %s connection' %
                            (proto_name))
                self.pdebug(DIGN | DFTP, '  %s' % (self.hdr_to_str(proto_name, hdr)))
                self.pdebug(DIGN | DFTP, '  Blacklisting port %d' % (sport))
                self.blacklist_ports[proto_name].append(sport)

            return True

        return False

    def maybe_redir_ip(self, label, pid, comm, ipver, hdr, proto_name, src_ip,
                       sport, skey, dst_ip, dport, dkey):
        """Conditionally redirect foreign destination IPs to localhost.

        Used only under SingleHost mode.

        Returns:
            None - if unmodified
            dpkt.ip.hdr - if modified
        """
        hdr_modified = None

        if self.check_should_ignore(pid, comm, ipver, hdr, proto_name, src_ip,
                                    sport, dst_ip, dport):
            return hdr_modified  # None

        self.pdebug(DIPNAT, 'Condition 1 test')
        # Condition 1: If the remote IP address is foreign to this system,
        # then redirect it to a local IP address.
        if self.single_host_mode and (dst_ip not in self.ip_addrs[ipver]):
            self.pdebug(DIPNAT, 'Condition 1 satisfied')
            self.ip_fwd_table_lock.acquire()
            try:
                self.ip_fwd_table[skey] = dst_ip

            finally:
                self.ip_fwd_table_lock.release()

            newdst = '127.0.0.1'
            hdr_modified = self.mangle_dstip(hdr, proto_name, dst_ip, newdst)

        else:
            # Delete any stale entries in the IP forwarding table: If the
            # local endpoint appears to be reusing a client port that was
            # formerly used to connect to a foreign host (but not anymore),
            # then remove the entry. This prevents a packet hook from
            # faithfully overwriting the source IP on a later packet to
            # conform to the foreign endpoint's stale connection IP when
            # the host is reusing the port number to connect to an IP
            # address that is local to the FakeNet system.

            self.ip_fwd_table_lock.acquire()
            try:
                if skey in self.ip_fwd_table:
                    self.pdebug(DIPNAT, ' - DELETING ipfwd key entry: ' + skey)
                    del self.ip_fwd_table[skey]
            finally:
                self.ip_fwd_table_lock.release()

        return hdr_modified

    def maybe_fixup_srcip(self, label, pid, comm, ipver, hdr, proto_name,
                          src_ip, sport, skey, dst_ip, dport, dkey):
        """Conditionally fix up the source IP address if the remote endpoint
        had their connection IP-forwarded.

        Check is based on whether the remote endpoint corresponds to a key in
        the IP forwarding table.

        Returns:
            None - if unmodified
            dpkt.ip.hdr - if modified
        """
        hdr_modified = None

        # Condition 4: If the local endpoint (IP/port/proto) combo
        # corresponds to an endpoint that initiated a conversation with a
        # foreign endpoint in the past, then fix up the source IP for this
        # incoming packet with the last destination IP that was requested
        # by the endpoint.
        self.pdebug(DIPNAT, "Condition 4 test: was remote endpoint IP fwd'd?")
        self.ip_fwd_table_lock.acquire()
        try:
            if self.single_host_mode and (dkey in self.ip_fwd_table):
                self.pdebug(DIPNAT, 'Condition 4 satisfied')
                self.pdebug(DIPNAT, ' = FOUND ipfwd key entry: ' + dkey)
                new_srcip = self.ip_fwd_table[dkey]
                hdr_modified = self.mangle_srcip(
                    hdr, proto_name, hdr.src, new_srcip)
            else:
                self.pdebug(DIPNAT, ' ! NO SUCH ipfwd key entry: ' + dkey)
        finally:
            self.ip_fwd_table_lock.release()

        return hdr_modified

    def maybe_redir_port(self, label, pid, comm, ipver, hdr, proto_name,
                         src_ip, sport, skey, dst_ip, dport, dkey):
        hdr_modified = None

        # Get default listener port for this proto, or bail if none
        default = None
        if not proto_name in self.default_listener:
            return hdr_modified  # None
        default = self.default_listener[proto_name]

        # Pre-condition 1: RedirectAllTraffic: Yes
        # NOTE: This only applies to port redirection in the Windows Diverter;
        # IP addresses will be modified by the Windows Diverter when
        # RedirectAllTraffic is disabled. So, the Linux Diverter implementation
        # will follow suit.
        if not self.is_set('redirectalltraffic'):
            self.pdebug(DIGN, 'Ignoring %s packet %s' %
                        (proto_name, self.hdr_to_str(proto_name, hdr)))
            return hdr_modified  # None

        # Pre-condition 1: destination must not be present in port forwarding
        # table (prevents masqueraded ports responding to unbound ports from
        # being mistaken as starting a conversation with an unbound port).
        found = False
        self.port_fwd_table_lock.acquire()
        try:
            # Uses dkey to cross-reference
            found = dkey in self.port_fwd_table
        finally:
            self.port_fwd_table_lock.release()

        if found:
            return hdr_modified  # None

        bound_ports = self.diverted_ports.get(proto_name, [])

        # Condition 2: If the packet is destined for an unbound port, then
        # redirect it to a bound port and save the old destination IP in
        # the port forwarding table keyed by the source endpoint identity.

        self.pdebug(DDPFV, 'Condition 2 test')

        if self.decide_redir_port(ipver, proto_name, default, bound_ports,
                                  src_ip, sport, dst_ip, dport):
            self.pdebug(DDPFV, 'Condition 2 satisfied')

            # Post-condition 1: General ignore conditions are not met, or this
            # is part of a conversation that is already being ignored.
            #
            # Placed after the decision to redirect for three reasons:
            # 1.) We want to ensure that the else condition below has a chance
            #     to check whether to delete a stale port forwarding table
            #     entry.
            # 2.) Checking these conditions is, on average, more expensive than
            #     checking if the packet would be redirected in the first
            #     place.
            # 3.) Reporting of packets that are being ignored (i.e. not
            #     redirected), which is integrated into this check, should only
            #     appear when packets would otherwise have been redirected.
            
            # Is this conversation already being ignored for DPF purposes?
            self.ignore_table_lock.acquire()
            try:
                if dkey in self.ignore_table and self.ignore_table[dkey] == sport:
                    # This is a reply (e.g. a TCP RST) from the
                    # non-port-forwarded server that the non-port-forwarded
                    # client was trying to talk to. Leave it alone.
                    return hdr_modified  # None
            finally:
                self.ignore_table_lock.release()

            if self.check_should_ignore(pid, comm, ipver, hdr, proto_name,
                                        src_ip, sport, dst_ip, dport):
                self.ignore_table_lock.acquire()
                try:
                    self.ignore_table[skey] = dport
                finally:
                    self.ignore_table_lock.release()
                return hdr_modified  # None

            # Record the foreign endpoint and old destination port in the port
            # forwarding table
            self.pdebug(DDPFV, ' + ADDING portfwd key entry: ' + skey)
            self.port_fwd_table_lock.acquire()
            try:
                self.port_fwd_table[skey] = dport
            finally:
                self.port_fwd_table_lock.release()

            hdr_modified = self.mangle_dstport(hdr, proto_name, dport, default)

            # Record the altered port for making the ExecuteCmd decision
            dport = default

        else:
            # Delete any stale entries in the port forwarding table: If the
            # foreign endpoint appears to be reusing a client port that was
            # formerly used to connect to an unbound port on this server,
            # remove the entry. This prevents the OUTPUT or other packet
            # hook from faithfully overwriting the source port to conform
            # to the foreign endpoint's stale connection port when the
            # foreign host is reusing the port number to connect to an
            # already-bound port on the FakeNet system.

            self.delete_stale_port_fwd_key(skey)

        if not (sport in self.sessions and self.sessions[sport] == (dst_ip,
                dport)):
            self.sessions[sport] = (dst_ip, dport)

            if pid and (dst_ip in self.ip_addrs[ipver]):
                cmd = self.build_cmd(proto_name, pid, comm, src_ip,
                                     sport, dst_ip, dport)
                if cmd:
                    self.logger.info('Executing command: %s', cmd)
                    self.execute_detached(cmd)

        return hdr_modified

    def delete_stale_port_fwd_key(self, skey):
        self.port_fwd_table_lock.acquire()
        try:
            if skey in self.port_fwd_table:
                self.pdebug(DDPFV, ' - DELETING portfwd key entry: ' + skey)
                del self.port_fwd_table[skey]
        finally:
            self.port_fwd_table_lock.release()

    def maybe_fixup_sport(self, label, pid, comm, ipver, hdr, proto_name,
                          src_ip, sport, skey, dst_ip, dport, dkey):
        """Conditionally fix up source port if the remote endpoint had their
        connection port-forwarded.

        Check is based on whether the remote endpoint corresponds to a key in
        the port forwarding table.

        Returns:
            None - if unmodified
            dpkt.ip.hdr - if modified
        """
        hdr_modified = None

        # Condition 3: If the remote endpoint (IP/port/proto) combo
        # corresponds to an endpoint that initiated a conversation with an
        # unbound port in the past, then fix up the source port for this
        # outgoing packet with the last destination port that was requested
        # by that endpoint. The term "endpoint" is (ab)used loosely here to
        # apply to UDP host/port/proto combos and any other protocol that
        # may be supported in the future.
        self.pdebug(DDPFV, "Condition 3 test: was remote endpoint port fwd'd?")
        self.port_fwd_table_lock.acquire()
        try:
            if dkey in self.port_fwd_table:
                self.pdebug(DDPFV, 'Condition 3 satisfied: must fix up ' +
                            'source port')
                self.pdebug(DDPFV, ' = FOUND portfwd key entry: ' + dkey)
                new_sport = self.port_fwd_table[dkey]
                hdr_modified = self.mangle_srcport(
                    hdr, proto_name, hdr.data.sport, new_sport)
            else:
                self.pdebug(DDPFV, ' ! NO SUCH portfwd key entry: ' + dkey)
        finally:
            self.port_fwd_table_lock.release()

        return hdr_modified

    def decide_redir_port(self, ipver, proto_name, default_port, bound_ports,
                          src_ip, sport, dst_ip, dport):
        """Decide whether to redirect a port.

        Optimized logic derived by truth table + k-map. See docs/internals.md
        for details.
        """
        # A, B, C, D for easy manipulation; full names for readability only.
        a = src_local = (src_ip in self.ip_addrs[ipver])
        c = sport_bound = sport in (bound_ports)
        d = dport_bound = dport in (bound_ports)

        if self.pdebug_level & DDPFV:
            # Unused logic term not calculated except for debug output
            b = dst_local = (dst_ip in self.ip_addrs[ipver])

            self.pdebug(DDPFV, 'src %s (%s)' %
                        (str(src_ip), ['foreign', 'local'][a]))
            self.pdebug(DDPFV, 'dst %s (%s)' %
                        (str(dst_ip), ['foreign', 'local'][b]))
            self.pdebug(DDPFV, 'sport %s (%sbound)' %
                        (str(sport), ['un', ''][c]))
            self.pdebug(DDPFV, 'dport %s (%sbound)' %
                        (str(dport), ['un', ''][d]))

            def bn(x): return '1' if x else '0'  # Bool -> binary
            self.pdebug(DDPFV, 'abcd = ' + bn(a) + bn(b) + bn(c) + bn(d))

        return (not a and not d) or (not c and not d)

    def mangle_dstip(self, hdr, proto_name, dstip, newdstip):
        """Mangle destination IP for selected outgoing packets."""
        self.pdebug(DIPNAT, 'REDIRECTING %s to IP %s' %
                    (self.hdr_to_str(proto_name, hdr), newdstip))
        hdr.dst = socket.inet_aton(newdstip)
        self._calc_csums(hdr)
        return hdr

    def mangle_srcip(self, hdr, proto_name, src_ip, new_srcip):
        """Mangle source IP for selected incoming packets."""
        self.pdebug(DIPNAT, 'MASQUERADING %s from IP %s' %
                    (self.hdr_to_str(proto_name, hdr), new_srcip))
        hdr.src = socket.inet_aton(new_srcip)
        self._calc_csums(hdr)
        return hdr

    def mangle_dstport(self, hdr, proto_name, dstport, newdstport):
        """Mangle destination port for selected incoming packets."""
        self.pdebug(DDPF, 'REDIRECTING %s to port %d' %
                          (self.hdr_to_str(proto_name, hdr), newdstport))
        hdr.data.dport = newdstport
        self._calc_csums(hdr)
        return hdr

    def mangle_srcport(self, hdr, proto_name, srcport, newsrcport):
        """Mangle source port for selected outgoing packets."""
        self.pdebug(DDPF, 'MASQUERADING %s from port %d' %
                          (self.hdr_to_str(proto_name, hdr), newsrcport))
        hdr.data.sport = newsrcport
        self._calc_csums(hdr)
        return hdr

    def hdr_to_str(self, proto_name, hdr):
        src_ip = socket.inet_ntoa(hdr.src)
        dst_ip = socket.inet_ntoa(hdr.dst)
        if proto_name:
            return '%s %s:%d->%s:%d' % (proto_name, src_ip, hdr.data.sport,
                                        dst_ip, hdr.data.dport)
        else:
            return '%s->%s' % (src_ip, dst_ip)

    def _calc_csums(self, hdr):
        """The roundabout dance of inducing dpkt to recalculate checksums."""
        hdr.sum = 0
        hdr.data.sum = 0
        str(hdr)  # This has the side-effect of invoking dpkt.in_cksum() et al


if __name__ == '__main__':
    logging.basicConfig(format='%(message)s')
    diverterbase.test_redir_logic(Diverter)
