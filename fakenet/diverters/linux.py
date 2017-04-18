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

b2 = lambda x: '1' if x else '0'

class PacketHandler:
    """Used to encapsulate common patterns in packet hooks."""

    def __init__(self, pkt, diverter, label, callbacks3, callbacks4):
        self.logger = logging.getLogger('Diverter')

        self.pkt = pkt
        self.diverter = diverter  # Relies on the Diverter for certain operations
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

            self.logger.debug('%s %s' % (self.label,
                        self.diverter._hdr_to_str(proto_name, self.hdr)))

            # 1B: Parse IP packet (actually done in ctor)
            self.src_ip = socket.inet_ntoa(self.hdr.src)
            self.dst_ip = socket.inet_ntoa(self.hdr.dst)

            # 2: Call layer 3 (network) callbacks
            for net_callback in self.callbacks3:
                net_callback(self.hdr, self.ipver, self.proto, proto_name,
                        self.src_ip, self.dst_ip)

            if proto_name and len(self.callbacks4):
                # 3: Parse higher-layer protocol
                self.sport = self.hdr.data.sport
                self.dport = self.hdr.data.dport
                self.skey = self.diverter.gen_endpoint_key(proto_name,
                        self.src_ip, self.sport)
                self.dkey = self.diverter.gen_endpoint_key(proto_name,
                        self.dst_ip, self.dport)

                hdr_latest = self.hdr
                modified = False

                # 4: Layer 4 (Transport layer) callbacks
                for trans_callback in self.callbacks4:
                    hdr_mod = trans_callback(self.ipver, hdr_latest,
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
                self.logger.debug('%s: Not handling protocol %s' %
                        (self.label, self.proto))

        # 5B: NF_ACCEPT
        self.pkt.accept()

class Diverter(DiverterBase, LinUtilMixin):
    def __init__(self, diverter_config, listeners_config, ip_addrs,
                 logging_level = logging.INFO):
        self.init_base(diverter_config, listeners_config, ip_addrs,
                       logging_level)

        # TODO: Remove this after testing and development are complete
        self.logger.setLevel(logging.DEBUG)

        self.init_diverter_linux()

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
            # TODO: Incorporate ICMP so that it appears in pcap and logging
            # dpkt.ip.IP_PROTO_ICMP: 'ICMP',
        }

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

    def start(self):
        self.logger.info('Starting Linux Diverter...')

        hookspec = namedtuple('hookspec', ['chain', 'table', 'callback'])

        callbacks = list()

        # In MultiHost mode, when foreign packets come in with a non-local
        # destination IP, they have to be examined in the PREROUTING chain in
        # order to observe the non-local address before it is mangled into a
        # local IP address by the NAT PREROUTING/REDIRECT rule (added by the
        # LinuxRedirectNonlocal configuratoin setting).
        #
        # In contrast, when using FakeNet-NG under SingleHost mode, packets
        # originated by processes within the system that are destined for
        # foreign IP addresses never hit the PREROUTING chain, making this hook
        # superfluous. That is why it is not applied when FakeNet-NG is in
        # SingleHost mode. Instead, the check is performed within the hook for
        # outgoing packets.
        if not self.single_host_mode:
            callbacks.append(hookspec('PREROUTING', 'raw', self.handle_nonlocal))

        callbacks.append(hookspec('INPUT', 'mangle', self.handle_incoming))
        callbacks.append(hookspec('OUTPUT', 'mangle', self.handle_outgoing))

        nhooks = len(callbacks)

        self.logger.debug('Discovering the next %d available NFQUEUE numbers' %
                (nhooks))
        qnos = self.linux_get_next_nfqueue_numbers(nhooks)
        if len(qnos) != nhooks:
            self.logger.error('Could not procure a sufficient number of ' +
                            'netfilter queue numbers')
            sys.exit(1)

        self.logger.debug('Next available NFQUEUE numbers: ' + str(qnos))

        self.logger.debug('Enumerating queue numbers and hook ' +
                'specifications to create NFQUEUE objects')
        self.nfqueues = list()
        for qno, hk in zip(qnos, callbacks):
            self.logger.debug(('Creating NFQUEUE object for chain %s / table ' +
                    '%s / queue # %d => %s') % (hk.chain, hk.table, qno,
                    str(hk.callback)))
            q = LinuxDiverterNfqueue(qno, hk.chain, hk.table, hk.callback)
            self.nfqueues.append(q)
            ok = q.start()
            if not ok:
                self.logger.error('Failed to start NFQUEUE for %s' % (str(q)))
                self.stop()
                sys.exit(1)

        if self.is_set('modifylocaldns'):
            self.linux_modifylocaldns_ephemeral()

        if self.is_configured('linuxflushdnscommand'):
            cmd = self.getconfigval('linuxflushdnscommand')
            ret = subprocess.call(cmd.split())
            if ret != 0:
                self.logger.error('Failed to flush DNS cache.')

        # TODO: Duplicate windows.Diverter code for
        #   * # Stop DNS service (if stopdnsservice)

        if self.is_configured('linuxredirectnonlocal'):
            self.logger.debug('Processing LinuxRedirectNonlocal')
            specified_ifaces = self.getconfigval('linuxredirectnonlocal')
            self.logger.debug('Processing linuxredirectnonlocal on ' +
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

    def stop(self):
        self.logger.info('Stopping Linux Diverter...')

        self.logger.debug('Notifying NFQUEUE objects of imminent stop')
        for q in self.nfqueues:
            q.stop_nonblocking()

        self.logger.debug('Removing iptables rules not associated with any ' +
                'NFQUEUE object')
        self.linux_remove_iptables_rules(self.rules_added)

        for q in self.nfqueues:
            self.logger.debug('Stopping NFQUEUE for %s' % (str(q)))
            q.stop()

        if self.pcap:
            self.logger.debug('Closing pcap file %s' % (self.pcap_filename))
            self.pcap.close()  # Only after all queues are stopped

        self.logger.info('Stopped Linux Diverter')

        if self.is_set('modifylocaldns'):
            self.linux_restore_local_dns()

        # TODO: Duplicate windows.Diverter code for
        #   * # Restart DNS service (if stopdnsservice)

    def parse_ipv4(self, ipver, raw):
        hdr = dpkt.ip.IP(raw)
        if hdr.hl < 5:
            return (None, None) # An IP header length less than 5 is invalid
        return hdr, hdr.p

    def parse_ipv6(self, ipver, raw):
        hdr = dpkt.ip6.IP6(raw)
        return hdr, hdr.nxt

    def gen_endpoint_key(self, proto_name, ip, port):
        """e.g. 192.168.19.132:tcp/3030"""
        return str(ip) + ':' + str(proto_name) + '/' + str(port)


    def _check_log_nonlocal(self, hdr, ipver, proto, proto_name, src_ip,
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

        self.logger.debug('Nonlocal %s' % (self._hdr_to_str(proto_name, hdr)))

        first_sighting = (dst_ip not in self.nonlocal_ips_already_seen)

        if first_sighting:
            self.nonlocal_ips_already_seen.append(dst_ip)

        # Log when a new IP is observed OR if we are not restricted to
        # logging only the first occurrence of a given nonlocal IP.
        if first_sighting or (not self.log_nonlocal_only_once):
            self.logger.info(
                'Received nonlocal IPv%d datagram destined for %s' %
                (ipver, dst_ip))

    def handle_nonlocal(self, pkt):
        """Handle comms sent to IP addresses that are not bound to any adapter.

        This allows analysts to observe when malware is communicating with
        hard-coded IP addresses.
        """

        net_cbs = [self._check_log_nonlocal,]

        h = PacketHandler(pkt, self, 'handle_nonlocal', net_cbs, [])
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
        net_cbs = [self._check_log_nonlocal] if self.single_host_mode else []

        trans_cbs = [
            self._maybe_fixup_sport,
            self._maybe_redir_ip,
        ]

        h = PacketHandler(pkt, self, 'handle_outgoing', net_cbs, trans_cbs)
        h.handle_pkt()

    def _maybe_fixup_srcip(self, ipver, hdr, proto_name, src_ip, sport, skey,
            dst_ip, dport, dkey):
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
        self.logger.debug("Condition 4 test: was remote endpoint IP fwd'd?")
        self.ip_fwd_table_lock.acquire()
        try:
            if self.single_host_mode and (dkey in self.ip_fwd_table):
                self.logger.debug('Condition 4 satisfied')
                self.logger.debug(' = FOUND ipfwd key entry: ' + dkey)
                new_srcip = self.ip_fwd_table[dkey]
                hdr_modified = self.mangle_srcip(hdr, proto_name, hdr.src, new_srcip)
            else:
                self.logger.debug(' ! NO SUCH ipfwd key entry: ' + dkey)
        finally:
            self.ip_fwd_table_lock.release()

        return hdr_modified

    def _maybe_redir_port(self, ipver, hdr, proto_name, src_ip, sport, skey,
            dst_ip, dport, dkey):
        hdr_modified = None

        default = self.default_listener[proto_name]
        bound_ports = self.diverted_ports.get(proto_name, [])

        # Pre-condition: destination not present in port forwarding table
        # (prevent masqueraded ports responding to unbound ports from being
        # mistaken as starting a conversation with an unbound port)
        self.port_fwd_table_lock.acquire()
        found = False
        try:
            # Uses dkey to cross-reference
            found = dkey in self.port_fwd_table
        finally:
            self.port_fwd_table_lock.release()

        # Condition 2: If the packet is destined for an unbound port, then
        # redirect it to a bound port and save the old destination IP in
        # the port forwarding table keyed by the source endpoint identity.

        self.logger.debug('Condition 2 test')

        if (not found) and self.decide_redir_port(ipver, proto_name, default, bound_ports, src_ip, sport, dst_ip, dport):
        # if self.decide_redir_port(ipver, proto_name, default, bound_ports, src_ip, sport, dst_ip, dport):
            self.logger.debug('Condition 2 satisfied')

            # Record the foreign endpoint and old destination port in the port
            # forwarding table
            self.logger.debug(' + ADDING portfwd key entry: ' + skey)
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
                    self.logger.debug(' - DELETING portfwd key entry: ' + skey)
                    del self.port_fwd_table[skey]
            finally:
                self.port_fwd_table_lock.release()

        return hdr_modified

    def _maybe_fixup_sport(self, ipver, hdr, proto_name, src_ip, sport, skey, dst_ip,
            dport, dkey):
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
        self.logger.debug("Condition 3 test: was remote endpoint port fwd'd?")
        self.port_fwd_table_lock.acquire()
        try:
            if dkey in self.port_fwd_table:
                self.logger.debug('Condition 3 satisfied: must fix up source port')
                self.logger.debug(' = FOUND portfwd key entry: ' + dkey)
                new_sport = self.port_fwd_table[dkey]
                hdr_modified = self.mangle_srcport(hdr, proto_name, hdr.data.sport, new_sport)
            else:
                self.logger.debug(' ! NO SUCH portfwd key entry: ' + dkey)
        finally:
            self.port_fwd_table_lock.release()

        return hdr_modified

    def _maybe_redir_ip(self, ipver, hdr, proto_name, src_ip, sport, skey, dst_ip,
            dport, dkey):
        """Conditionally redirect foreign destination IPs to localhost.

        Used only under SingleHost mode.

        Returns:
            None - if unmodified
            dpkt.ip.hdr - if modified
        """
        self.logger.debug('Condition 1 test')
        # Condition 1: If the remote IP address is foreign to this system,
        # then redirect it to a local IP address.
        hdr_modified = None

        if self.single_host_mode and (dst_ip not in self.ip_addrs[ipver]):
            self.logger.debug('Condition 1 satisfied')
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
                    self.logger.debug(' - DELETING ipfwd key entry: ' + skey)
                    del self.ip_fwd_table[skey]
            finally:
                self.ip_fwd_table_lock.release()

        return hdr_modified

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
        trans_cbs = [
            self._maybe_fixup_srcip,
            self._maybe_redir_port,
        ]

        h = PacketHandler(pkt, self, 'handle_incoming', [], trans_cbs)
        h.handle_pkt()

    def decide_redir_port(self, ipver, proto_name, default_port, bound_ports, src_ip, sport, dst_ip, dport):
        if not self.is_set('redirectalltraffic'):
            return False

        if proto_name == 'TCP':
            if dport in self.getconfigval('blacklistportstcp'):
                self.logger.debug('Not forwarding packet destined for tcp/%d' % (dport))
                return False
        elif proto_name == 'UDP':
            if dport in self.getconfigval('blacklistportsudp'):
                self.logger.debug('Not forwarding packet destined for udp/%d' % (dport))
                return False

        # A, B, C, and D are for easy calculation of sum-of-products logical result
        # Full names are present for readability
        # TODO: Add commentation explaining minterms and SOP logic derived from
        # redir_logic.xlsx
        a = src_ip_is_local = (src_ip in self.ip_addrs[ipver])
        b = dst_ip_is_local = (dst_ip in self.ip_addrs[ipver])

        c = src_port_is_bound = sport in (bound_ports)
        d = dst_port_is_bound = dport in (bound_ports)

        self.logger.debug('srcip: ' + str(src_ip) + (' (local)' if a else ' (foreign)'))
        self.logger.debug('dstip: ' + str(dst_ip) + (' (local)' if b else ' (foreign)'))
        self.logger.debug('srcpt: ' + str(sport) + (' (bound)' if c else ' (unbound)'))
        self.logger.debug('dstpt: ' + str(dport) + (' (bound)' if d else ' (unbound)'))

        result = (
            (dst_ip_is_local and not src_ip_is_local and not dst_port_is_bound) or
            (src_ip_is_local and not src_port_is_bound and not dst_port_is_bound)
        )

        result = (b and not a and not d) or (a and not c and not d)

        self.logger.debug('abcd = ' + b2(a) + b2(b) + b2(c) + b2(d))

        return result

    def mangle_dstip(self, hdr, proto_name, dstip, newdstip):
        """Mangle destination IP for selected outgoing packets."""
        self.logger.debug('REDIRECTING %s to IP %s' %
                (self._hdr_to_str(proto_name, hdr), newdstip))
        hdr.dst = socket.inet_aton(newdstip)
        self._calc_csums(hdr)
        return hdr

    def mangle_srcip(self, hdr, proto_name, src_ip, new_srcip):
        """Mangle source IP for selected incoming packets."""
        self.logger.debug('MASQUERADING %s from IP %s' %
                (self._hdr_to_str(proto_name, hdr), new_srcip))
        hdr.src = socket.inet_aton(new_srcip)
        self._calc_csums(hdr)
        return hdr

    def mangle_dstport(self, hdr, proto_name, dstport, newdstport):
        """Mangle destination port for selected incoming packets."""
        self.logger.debug('REDIRECTING %s to port %d' %
                (self._hdr_to_str(proto_name, hdr), newdstport))
        hdr.data.dport = newdstport
        self._calc_csums(hdr)
        return hdr

    def mangle_srcport(self, hdr, proto_name, srcport, newsrcport):
        """Mangle source port for selected outgoing packets."""
        self.logger.debug('MASQUERADING %s from port %d' %
                (self._hdr_to_str(proto_name, hdr), newsrcport))
        hdr.data.sport = newsrcport
        self._calc_csums(hdr)
        return hdr

    def _hdr_to_str(self, proto_name, hdr):
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
