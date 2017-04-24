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
from collections import namedtuple
from diverterbase import DiverterBase
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
            for net_cb in self.callbacks3:
                net_cb(self.hdr, self.ipver, self.proto, proto_name,
                       self.src_ip, self.dst_ip)

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
                    if pid:
                        self.logger.info('  pid:  %d name: %s' %
                                         (pid, comm if comm else 'Unknown'))

                    hdr_latest = self.hdr
                    modified = False

                    # 4: Layer 4 (Transport layer) callbacks
                    for trans_cb in self.callbacks4:
                        hdr_mod = trans_cb(pid, comm, self.ipver, hdr_latest,
                                           proto_name,
                                           self.src_ip, self.sport, self.skey,
                                           self.dst_ip, self.dport, self.dkey)
                        if hdr_mod:
                            hdr_latest = hdr_mod
                            modified = True

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

        self.set_debug_level(DIGN, DLABELS)

        self.init_diverter_linux()
        self.init_linux_mixin()

    def init_diverter_linux(self):
        """Linux-specific Diverter initialization."""
        # String list configuration item that is specific to the Linux
        # Diverter, will not be parsed by DiverterBase, and needs to be
        # accessed as an array in the future.
        self.reconfigure(portlists=[], stringlists=['linuxredirectnonlocal'])

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

        self.logger.info('Running in %s mode' % (mode))

        self.parse_pkt = dict()
        self.parse_pkt[4] = self.parse_ipv4
        self.parse_pkt[6] = self.parse_ipv6

        self.nfqueues = list()

        self.handled_protocols = {
            dpkt.ip.IP_PROTO_TCP: 'TCP',
            dpkt.ip.IP_PROTO_UDP: 'UDP',
        }
        # TODO: Incorporate ICMP so that it appears in pcap and logging but
        # doesn't trigger layer4 processing: dpkt.ip.IP_PROTO_ICMP / 'ICMP'

        # Track iptables rules not associated with any nfqueue object
        self.rules_added = []

        # Manage logging of foreign-destined packets
        self.nonlocal_ips_already_seen = []
        self.log_nonlocal_only_once = True

        # Port forwarding table, for looking up original unbound service ports
        # when sending replies to foreign endpoints that have attempted to
        # communicate with unbound ports. Allows fixing up source ports in
        # response packets.
        self.port_fwd_table = dict()
        self.port_fwd_table_lock = threading.Lock()

        # IP forwarding table, for looking up original foreign destination IPs
        # when sending replies to local endpoints that have attempted to
        # communicate with other machines e.g. via hard-coded C2 IP addresses.
        self.ip_fwd_table = dict()
        self.ip_fwd_table_lock = threading.Lock()

        # NOTE: Constraining cache size via LRU or similar is a non-requirement
        # due to the short anticipated runtime of FakeNet-NG. If you see your
        # FakeNet-NG consuming large amounts of memory, contact your doctor to
        # find out if Ctrl+C is right for you.

    def start(self):
        self.logger.info('Starting Linux Diverter...')

        ret = self.linux_capture_iptables()
        if ret != 0:
            sys.exit(1)

        hookspec = namedtuple('hookspec', ['chain', 'table', 'callback'])

        callbacks = list()

        # TODO: While we're documenting things, let's include:
        # 1.) The components that compose the Linux Diverter
        # 2.) The traffic flow relevant to conditions 1-4
        #
        # EXPLAINING HOOK LOCATION CHOICES
        #
        # This can be moved into a TXT file and added to the git repo if this
        # implementation remains relevant.
        #
        # Observing packets destined for non-local IP addresses
        # -----------------------------------------------------
        #
        # In MultiHost mode, when foreign packets come in having a non-local
        # destination IP, they have to be examined in the PREROUTING chain in
        # order to observe the non-local address before it is mangled into a
        # local IP address by the IP NAT (PREROUTING/REDIRECT) rule added by
        # the LinuxRedirectNonlocal configuration setting.
        #
        # In contrast, when using FakeNet-NG under SingleHost mode, packets
        # originated by processes within the system that are destined for
        # foreign IP addresses never hit the PREROUTING chain, making this hook
        # superfluous. That is why it is not applied when FakeNet-NG is in
        # SingleHost mode. Instead, the logging for IP addresses having
        # non-local destination IP addresses is performed within the hook for
        # outgoing packets.
        #
        # Dynamic port forwarding in concert with IP NAT
        # ----------------------------------------------
        #
        # In both MultiHost and SingleHost mode, FakeNet-NG implements dynamic
        # port forwarding (DPF) by mangling packets on their way in and out of
        # the system. Incoming packets destined for an unbound port are
        # modified to point to a default destination port and the packet
        # checksums are recalculated. The remote endpoint's IP address,
        # protocol, and port are saved in a port forwarding lookup table - much
        # like Netfilter's NAT implementation that will be explained
        # subsequently - to be able to recognize outgoing reply packets and
        # mangle them to provide the illusion that the remote host is
        # communicating with the port that it asked for. If an outgoing
        # packet's remote endpoint corresponds to a port forwarding table
        # entry, the source port is fixed up so that the remote TCP stack does
        # not perceive any issue with FakeNet-NG's replies.
        # 
        # Meanwhile, in MultiHost mode, IP NAT via the iptables REDIRECT target
        # works by using conntrack to record tuples of information about
        # packets going in one direction so that reply packets going in the
        # opposite direction can be recognized. By recording and referring to
        # this information, conntrack is able to likewise correctly fix up the
        # IP addresses in reply packets. The conntrack module uses information
        # like TCP ports to recognize what packets need to be fixed up.
        # Therefore, it is necessary to perform all DPF-related mangling of TCP
        # ports on one side or the other of the NAT so that conntrack
        # symmetrically and uniformly observes either client-side or
        # DPF-mangled port numbers whenever it is calculating tuples to
        # determine a NAT match and mangle the packet to reflect the correct
        # source IP address. Incorrect chain/table placement of incoming and
        # outgoing packet hooks will result in IP NAT failing to recognize and
        # fix up reply packets. On the client side, this can be observed to
        # manifest itself as (1) TCP SYN/ACK packets coming from the FakeNet-NG
        # host that do not mirror the arbitrary IP addresses that the client is
        # asking to talk to, and consequently (2) TCP RST packets from the
        # client due to the erroneous SYN/ACK responses it is receiving: no
        # three-way handshake, no TCP connection, and no exchange of data.
        #
        # Why not implement IP NAT ourselves? We are already using
        # python-netfilterqueue to manipulate and observe packet traversal.
        # Well, conntrack handles protocols other than TCP/IP (such as ICMP)
        # and implements a rich library of protocol modules for reaching above
        # the network layer to recognize connections for protocols such as IRC,
        # FTP, etc. We're not going to do a better job than that, and we don't
        # want to reinvent the wheel if we can avoid it. In fact, TODO: we
        # ought to revisit the SingleHost implementation to see if we can
        # benefit from using an iptables OUTPUT/REDIRECT rule there to replace
        # our current packet mangling implementation.
        #
        # In any event, here are the locations where it is okay to place the
        # incoming and outgoing packet hooks so that we don't disrupt
        # conntrack:
        #
        #         Incoming                          Outgoing
        # Chain             Tables          Chain           Tables          
        # ---------------------------------------------------------------------
        # PREROUTING        raw             OUTPUT          mangle,nat,filter
        #                                   POSTROUTING     (any)
        #
        # INPUT             (any)           OUTPUT          raw
        #
        # A handy graphic depicting Netfilter chains and tables in detail can
        # be found at:
        #
        # https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-
        # flow.svg
        #
        # Code relating to NAT redirection and connection tracking can be found
        # in the Linux kernel in the following files/functions (both IPv4 and
        # IPv6 information are available but only IPv4 is mentioned here):
        #
        # net/netfilter/xt_REDIRECT.c: redirect_tg4()
        # net/netfilter/nf_nat_redirect.c: nf_nat_redirect_ipv4()
        # net/netfilter/nf_nat_core.c: nf_nat_setup_info()
        #
        # Documentation relating to NAT redirection and connection tracking can
        # be found at:
        #
        # https://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO
        # -4.html#toc4.4

        if not self.single_host_mode:
            callbacks.append(hookspec('PREROUTING', 'raw',
                                      self.handle_nonlocal))

        callbacks.append(hookspec('INPUT', 'mangle', self.handle_incoming))
        callbacks.append(hookspec('OUTPUT', 'raw', self.handle_outgoing))

        nhooks = len(callbacks)

        self.pdebug(DNFQUEUE, 'Discovering the next %d available NFQUEUE numbers' %
                          (nhooks))
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
                               'table %s / queue # %d => %s') % (hk.chain,
                               hk.table, qno, str(hk.callback)))
            q = LinuxDiverterNfqueue(qno, hk.chain, hk.table, hk.callback)
            self.nfqueues.append(q)
            ok = q.start()
            if not ok:
                self.logger.error('Failed to start NFQUEUE for %s' % (str(q)))
                self.stop()
                sys.exit(1)

        if self.is_set('fixgateway'):
            if not self.linux_get_default_gw():
                self.linux_set_default_gw()

        if self.is_set('modifylocaldns'):
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

        if self.is_set('modifylocaldns'):
            self.linux_restore_local_dns()

        self.linux_restore_iptables()

    def handle_nonlocal(self, pkt):
        """Handle comms sent to IP addresses that are not bound to any adapter.

        This allows analysts to observe when malware is communicating with
        hard-coded IP addresses.
        """

        net_cbs = [self.check_log_nonlocal]

        h = PacketHandler(pkt, self, 'handle_nonlocal', net_cbs, [])
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
        trans_cbs = [self.maybe_redir_port]

        # IP redirection fix-ups are only for SingleHost mode
        if self.single_host_mode:
            trans_cbs.append(self.maybe_fixup_srcip)

        h = PacketHandler(pkt, self, 'handle_incoming', [], trans_cbs)
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

        # Must scan for nonlocal packets in the output hook and at the network
        # layer (regardless of whether supported protocols like TCP/UDP can be
        # parsed) when using the SingleHost mode of FakeNet-NG. Note that if
        # this check were performed when FakeNet-NG is operating in MultiHost
        # mode, every response packet generated by a listener and destined for
        # a remote host would erroneously be sent for potential logging as
        # nonlocal host communication.
        net_cbs = [self.check_log_nonlocal] if self.single_host_mode else []

        trans_cbs = [self.maybe_fixup_sport]

        # IP redirection is only for SingleHost mode
        if self.single_host_mode:
            trans_cbs.append(self.maybe_redir_ip)

        h = PacketHandler(pkt, self, 'handle_outgoing', net_cbs, trans_cbs)
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

    def check_log_nonlocal(self, hdr, ipver, proto, proto_name, src_ip,
                            dst_ip):
        if dst_ip not in self.ip_addrs[ipver]:
            self._maybe_log_nonlocal(hdr, ipver, proto, dst_ip)

    def _maybe_log_nonlocal(self, hdr, ipver, proto, dst_ip):
        """Conditionally log packets having a foreign destination.

        Each foreign destination will be logged only once if the Linux
        Diverter's internal log_nonlocal_only_once flag is set. Otherwise, any
        foreign destination IP address will be logged each time it is observed.
        """
        proto_name = self.handled_protocols.get(proto)

        self.pdebug(DNONLOC, 'Nonlocal %s' % (self.hdr_to_str(proto_name, hdr)))

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
                    self.pdebug(DIGN, 'Ignoring %s packet from process %s in the process blacklist.' % (proto_name, comm))
                    self.pdebug(DIGN, '  %s' % (self.hdr_to_str(proto_name, hdr)))
                    return True
                elif (len(self.whitelisted_processes) and (comm not in
                        self.whitelisted_processes)):
                    self.pdebug(DIGN, 'Ignoring %s packet from process %s not in the process whitelist.' % (proto_name, comm))
                    self.pdebug(DIGN, '  %s' % (self.hdr_to_str(proto_name, hdr)))
                    return True

        # MultiHost mode checks
        else:
            pass  # None as of yet

        # Checks independent of mode

        if set(self.blacklist_ports[proto_name]).intersection([sport, dport]):
            self.pdebug(DIGN, 'Forwarding blacklisted port %s packet:' % (proto_name))
            self.pdebug(DIGN, '  %s' % (self.hdr_to_str(proto_name, hdr)))
            return True

        global_host_blacklist = self.getconfigval('hostblacklist')
        if global_host_blacklist and dst_ip in global_host_blacklist:
            self.pdebug(DIGN, 'Ignoring %s packet to %s in the host blacklist.' % (proto_name, dst_ip))
            self.pdebug(DIGN, '  %s' % (self.hdr_to_str(proto_name, hdr)))
            return True

        if comm:
            # Check per-listener whitelisted process list
            if dport in self.port_process_whitelist:
                # If program does NOT match whitelist
                if not comm in self.port_process_whitelist[dport]:
                    self.pdebug(DIGN, 'Ignoring %s request packet from process %s not in the listener process whitelist.' % (proto_name, process_name))
                    self.pdebug(DIGN, '  %s' % (self.hdr_to_str(proto_name, hdr)))
                    return True

            # Check per-listener blacklisted process list
            if dport in self.port_process_blacklist:
                # If program DOES match blacklist
                if comm in self.port_process_blacklist[dport]:
                    self.pdebug(DIGN, 'Ignoring %s request packet from process %s in the listener process blacklist.' % (proto_name, process_name))
                    self.pdebug(DIGN, '  %s' % (self.hdr_to_str(proto_name, hdr)))

                    return True

        if dport in self.port_host_whitelist:
            # If host does NOT match whitelist
            if not dst_ip in self.port_host_whitelist:
                self.pdebug(DIGN, 'Ignoring %s request packet to %s not in the listener host whitelist.', proto_name, packet.dst_addr)
                self.pdebug(DIGN, '  %s' % (self.hdr_to_str(proto_name, hdr)))
                return True

        if dport in self.port_host_blacklist:
            # If host DOES match blacklist
            if dst_ip in self.port_host_blacklist:
                self.pdebug(DIGN, 'Ignoring %s request packet to %s in the listener host blacklist.', proto_name, packet.dst_addr)
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

        # TODO: FTP hack only works in MultiHost mode, need to fix for
        # SingleHost mode.
        if ( (pid == os.getpid()) and ((dst_ip in self.ip_addrs[ipver]) and
                    (not dst_ip.startswith('127.'))) and ((src_ip in
                    self.ip_addrs[ipver]) and (not dst_ip.startswith('127.')))
                    and (not set([sport,
                    dport]).intersection(self.diverted_ports.keys()))
            ):
            self.pdebug(DIGN, 'Listener initiated %s connection' %
                    (proto_name))
            self.pdebug(DIGN, '  %s' % (self.hdr_to_str(proto_name, hdr)))
            self.pdebug(DIGN, '  Blacklisting port %d' % (sport))
            self.blacklist_ports[proto_name].append(sport)
            return True

        return False

    def maybe_redir_ip(self, pid, comm, ipver, hdr, proto_name, src_ip, sport,
            skey, dst_ip, dport, dkey):
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

            # TODO: Try 127.0.0.1, but may need this to be 192.168.x.x
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

    def maybe_fixup_srcip(self, pid, comm, ipver, hdr, proto_name, src_ip,
            sport, skey, dst_ip, dport, dkey):
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

    def maybe_redir_port(self, pid, comm, ipver, hdr, proto_name, src_ip,
            sport, skey, dst_ip, dport, dkey):
        hdr_modified = None

        if self.check_should_ignore(pid, comm, ipver, hdr, proto_name, src_ip,
                sport, dst_ip, dport):
            return hdr_modified  # None

        default = self.default_listener[proto_name]
        bound_ports = self.diverted_ports.get(proto_name, [])

        # Pre-condition 2: destination not present in port forwarding table
        # (prevent masqueraded ports responding to unbound ports from being
        # mistaken as starting a conversation with an unbound port).
        found = False
        self.port_fwd_table_lock.acquire()
        try:
            # Uses dkey to cross-reference
            found = dkey in self.port_fwd_table
        finally:
            self.port_fwd_table_lock.release()

        if found:
            return hdr_modified  # None

        # Condition 2: If the packet is destined for an unbound port, then
        # redirect it to a bound port and save the old destination IP in
        # the port forwarding table keyed by the source endpoint identity.

        self.pdebug(DDPF, 'Condition 2 test')

        if self.decide_redir_port(ipver, proto_name, default, bound_ports,
                                  src_ip, sport, dst_ip, dport):
            self.pdebug(DDPF, 'Condition 2 satisfied')

            # Record the foreign endpoint and old destination port in the port
            # forwarding table
            self.pdebug(DDPF, ' + ADDING portfwd key entry: ' + skey)
            self.port_fwd_table_lock.acquire()
            try:
                self.port_fwd_table[skey] = dport
            finally:
                self.port_fwd_table_lock.release()

            hdr_modified = self.mangle_dstport(hdr, proto_name, dport, default)

        else:
            # Delete any stale entries in the port forwarding table: If the
            # foreign endpoint appears to be reusing a client port that was
            # formerly used to connect to an unbound port on this server,
            # remove the entry. This prevents the OUTPUT or other packet
            # hook from faithfully overwriting the source port to conform
            # to the foreign endpoint's stale connection port when the
            # foreign host is reusing the port number to connect to an
            # already-bound port on the FakeNet system.

            self.port_fwd_table_lock.acquire()
            try:
                if skey in self.port_fwd_table:
                    self.pdebug(DDPF, ' - DELETING portfwd key entry: ' + skey)
                    del self.port_fwd_table[skey]
            finally:
                self.port_fwd_table_lock.release()

        return hdr_modified

    def maybe_fixup_sport(self, pid, comm, ipver, hdr, proto_name, src_ip,
            sport, skey, dst_ip, dport, dkey):
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
        self.pdebug(DDPF, "Condition 3 test: was remote endpoint port fwd'd?")
        self.port_fwd_table_lock.acquire()
        try:
            if dkey in self.port_fwd_table:
                self.pdebug(DDPF, 
                    'Condition 3 satisfied: must fix up source port')
                self.pdebug(DDPF, ' = FOUND portfwd key entry: ' + dkey)
                new_sport = self.port_fwd_table[dkey]
                hdr_modified = self.mangle_srcport(
                    hdr, proto_name, hdr.data.sport, new_sport)
            else:
                self.pdebug(DDPF, ' ! NO SUCH portfwd key entry: ' + dkey)
        finally:
            self.port_fwd_table_lock.release()

        return hdr_modified

    def decide_redir_port(self, ipver, proto_name, default_port, bound_ports,
                          src_ip, sport, dst_ip, dport):
        """Decide whether to redirect a port.

        Optimized logic derived by truth table + k-map. See below for details.

        Truth table key:
            src     source IP address
            sport   source port
            dst     source IP address
            dport   source port
            lsrc    src is local
            ldst    dst is local
            bsport  sport is in the set of ports bound by FakeNet-NG listeners
            bdport  dport is in the set of ports bound by FakeNet-NG listeners
            R?      Redirect?
            m       Minterm (R? == 1)

        Short names for convenience --> A       B       C       D       R
        src     sport   dst     dport   lsrc    ldst    bsport  dsport  R?  m
        -----------------------------------------------------------------------
        Foreign Unbound Foreign Unbound 0       0       0       0       1   *
        Foreign Unbound Foreign Bound   0       0       0       0       0
        Foreign Bound   Foreign Unbound 0       0       0       0       1   *
        Foreign Bound   Foreign Bound   0       0       0       0       0
        Foreign Unbound Local   Unbound 0       0       0       0       1   *
        Foreign Unbound Local   Bound   0       0       0       0       0
        Foreign Bound   Local   Unbound 0       0       0       0       1   *
        Foreign Bound   Local   Bound   0       0       0       0       0

        (Rationale: When a foreign host is trying to talk to us or anyone else
        in MultiHost mode, ensure unbound ports get redirected to a listener)

        Local   Unbound Foreign Unbound 0       0       0       0       1   *
        Local   Unbound Foreign Bound   0       0       0       0       0
        Local   Bound   Foreign Unbound 0       0       0       0       0
        Local   Bound   Foreign Bound   0       0       0       0       0
        Local   Unbound Local   Unbound 0       0       0       0       1   *
        Local   Unbound Local   Bound   0       0       0       0       0
        Local   Bound   Local   Unbound 0       0       0       0       0
        Local   Bound   Local   Bound   0       0       0       0       0

        (Rationale: In SingleHost mode, the local machine will wind up talking
        to itself if it tries to get out to a foreign IP. When the local
        machine is talking to itself in SingleHost mode, ensure unbound
        destination ports are redirected /except/ when the packet originates
        from a bound port. )

        Karnaugh map (zeroes omitted for readability):
                 CD
           AB \  00   01   11   10
               +-------------------.
            00 |  1 |    |    |  1 | -> A'D'
               +----+----+----+----+
            01 |  1 |    |    |  1 |
               +----+----+----+----+
            11 |  1 |    |    |    |
               +----+----+----+----+
            10 |  1 |    |    |    |
               +----+----+----+----+
                 |
                 V
                C'D'

        Minimized sum-of-products logic function:
            R(A, B, C, D) = A'D' + C'D'
        """
        if not self.is_set('redirectalltraffic'):
            return False

        # A, B, C, D for easy manipulation; full names for readability only.
        a = src_local = (src_ip in self.ip_addrs[ipver])
        c = sport_bound = sport in (bound_ports)
        d = dport_bound = dport in (bound_ports)

        if self.pdebug_level & DDPF:
            # Unused logic term not calculated except for debug output
            b = dst_local = (dst_ip in self.ip_addrs[ipver])

            self.pdebug(DDPF, 'src %s (%s)' %(str(src_ip), ['foreign','local'][a]))
            self.pdebug(DDPF, 'dst %s (%s)' %(str(dst_ip), ['foreign','local'][b]))
            self.pdebug(DDPF, 'sport %s (%sbound)' %(str(sport), ['un', ''][c]))
            self.pdebug(DDPF, 'dport %s (%sbound)' %(str(sport), ['un', ''][d]))
            def bn(x): return '1' if x else '0'  # Bool -> binary
            self.pdebug(DDPF, 'abcd = ' + bn(a) + bn(b) + bn(c) + bn(d))

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
            return 'unknown protocol %s->%s' % (src_ip, dst_ip)

    def _calc_csums(self, hdr):
        """The roundabout dance of inducing dpkt to recalculate checksums."""
        hdr.sum = 0
        hdr.data.sum = 0
        str(hdr)  # This has the side-effect of invoking dpkt.in_cksum() et al

if __name__ == '__main__':
    logging.basicConfig(format='%(message)s')
    diverterbase.test_redir_logic(Diverter)
