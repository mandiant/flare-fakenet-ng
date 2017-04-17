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

class Diverter(DiverterBase, LinUtilMixin):
    def __init__(self, diverter_config, listeners_config, ip_addrs,
                 logging_level = logging.INFO):
        self.init_base(diverter_config, listeners_config, ip_addrs,
                       logging_level)
        self.init_diverter_linux()

        self.logger.setLevel(logging.DEBUG)
        self.localmode = True

    def init_diverter_linux(self):
        """Linux-specific Diverter initialization."""
        # The Linux-specific Diverter accepts a string list configuration item
        # that is specific to the Linux Diverter which will not be parsed by
        # DiverterBase and needs to be accessed as an array in the future.
        self.reconfigure(portlists=[], stringlists=['linuxredirectnonlocal'])

        self.parse_pkt = dict()
        self.parse_pkt[4] = self.parse_ipv4
        self.parse_pkt[6] = self.parse_ipv6
        self._queues = list()

        self.handled_protocols = {
            dpkt.ip.IP_PROTO_TCP: 'TCP',
            dpkt.ip.IP_PROTO_UDP: 'UDP',
            # TODO: Incorporate ICMP so that it appears in pcap and logging
            # dpkt.ip.IP_PROTO_ICMP: 'ICMP',
        }

        # Track iptables rules not associated with any nfqueue object.
        self.rules_added = []

        # Manage (non-)logging already-seen nonlocal destination IPs in
        # incoming packets.
        self.nonlocal_ips = []
        self.log_nonlocal_once = True

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
        self.logger.info('Starting...')

        hookspec = namedtuple('hookspec', ['chain', 'table', 'callback'])

        callbacks = list()

        # May add conditional logic later to apply hooks based on configuration
        callbacks.append(hookspec('PREROUTING', 'raw', self.handle_nonlocal))
        callbacks.append(hookspec('INPUT', 'mangle', self.handle_incoming))
        callbacks.append(hookspec('OUTPUT', 'mangle', self.handle_outgoing))

        nhooks = len(callbacks)

        # Discover the next N available NFQUEUE numbers and install hooks
        qnos = self.linux_get_next_nfqueue_numbers(nhooks)
        if len(qnos) != nhooks:
            self.logger.error('Could not procure a sufficient number of ' +
                            'netfilter queue numbers')
            sys.exit(1)

        self.logger.debug('Next available NFQUEUE numbers: ' + str(qnos))

        # Create a list of queues based on the hook specifications and
        # netfilter queue numbers from above, and start each queue.
        self._queues = list()
        for qno, hk in zip(qnos, callbacks):
            q = LinuxDiverterNfqueue(qno, hk.chain, hk.table, hk.callback)
            self._queues.append(q)
            ok = q.start()
            if not ok:
                self.logger.error('Failed to start NFQUEUE for %s' % (str(q)))
                self.stop()
                sys.exit(1)

        # TODO: Duplicate windows.Diverter code for
        #   * # Set local DNS server IP address (if modifylocaldns)
        #   * # Stop DNS service (if stopdnsservice)
        #   * self.flush_dns() # ipconfig /flushdns

        if self.is_configured('linuxredirectnonlocal'):
            specified_ifaces = self.getconfigval('linuxredirectnonlocal')
            ok, rules = self.linux_redir_nonlocal(specified_ifaces)

            # Irrespective of whether this failed, we want to add any
            # successful iptables rules to the list so that stop() will be able
            # to remove them using linux_remove_iptables_rules().
            self.rules_added += rules

            if not ok:
                self.stop()
                sys.exit(1)

    def stop(self):
        self.logger.info('Stopping...')

        self.logger.debug('Notifying netfilter queue objects of imminent ' +
            'stop')
        for q in self._queues:
            q.stop_nonblocking()

        self.logger.debug('Removing iptables rules')
        self.linux_remove_iptables_rules(self.rules_added)

        for q in self._queues:
            self.logger.debug('Stopping NFQUEUE for %s' % (str(q)))
            q.stop()

        if self.pcap:
            self.pcap.close()  # Only after all queues are stopped

        self.logger.info('Stopped')

        # TODO: Duplicate windows.Diverter code for
        #   * # Restore DNS server (if modifylocaldns)
        #   * # Restart DNS service (if stopdnsservice)
        #   * self.flush_dns() # ipconfig /flushdns

    def parse_ipv4(self, ipver, raw):
        hdr = dpkt.ip.IP(raw)
        if hdr.hl < 5:
            return (-1, -1) # An IP header length less than 5 is invalid
        return hdr, hdr.p

    def parse_ipv6(self, ipver, raw):
        hdr = dpkt.ip6.IP6(raw)
        return hdr, hdr.nxt

    def gen_endpoint_key(self, proto_name, ip, port):
        """e.g. 192.168.19.132:tcp/3030"""
        return str(ip) + ':' + str(proto_name) + '/' + str(port)

    def handle_nonlocal(self, pkt):
        """Handle comms sent to IP addresses that are not bound to any adapter.

        This allows analysts to observe when malware is communicating with
        hard-coded IP addresses.
        """
        self.logger.debug('handle_pkt_redirected...')
        raw = pkt.get_payload()
        ipver = ((ord(raw[0]) & 0xf0) >> 4)
        hdr, proto = self.parse_pkt[ipver](ipver, raw)

        dst_ip = socket.inet_ntoa(hdr.dst)

        if dst_ip not in self.ip_addrs[ipver]:
            new_ip = (dst_ip not in self.nonlocal_ips)

            if new_ip:
                self.nonlocal_ips.append(dst_ip)

            # Log when a new IP is observed OR if we are not restricted to
            # logging only the first occurrence of a given nonlocal IP.
            if new_ip or (not self.log_nonlocal_once):
                self.logger.info(
                    'Received nonlocal IPv%d datagram destined for %s' %
                    (ipver, dst_ip))

        pkt.accept()

    def handle_outgoing(self, pkt):
        self.logger.debug('handle_outgoing...')
        raw = pkt.get_payload()
        ipver = ((ord(raw[0]) & 0xf0) >> 4)
        hdr, proto = self.parse_pkt[ipver](ipver, raw)

        # Write original, unmangled packet regardless of protocol
        self.write_pcap(hdr.pack())

        proto_name = self.handled_protocols.get(proto)

        if proto_name:
            src_ip = socket.inet_ntoa(hdr.src)
            sport = hdr.data.sport

            dst_ip = socket.inet_ntoa(hdr.dst)
            dport = hdr.data.dport

            # Port forwarding key based on destination
            pkey = self.gen_endpoint_key(proto_name, dst_ip, dport)

            # IP forwarding key based on source
            ikey = self.gen_endpoint_key(proto_name, src_ip, sport)

            self.logger.debug('Outgoing %s %s:%s->%s:%s' % (proto_name, src_ip, sport, dst_ip, dport))

            self.logger.debug('Condition 3 test')
            # Condition 3: If the remote endpoint (IP/port/proto) combo
            # corresponds to an endpoint that initiated a conversation with an
            # unbound port in the past, then fix up the source port for this
            # outgoing packet with the last destination port that was requested
            # by that endpoint. The term "endpoint" is (ab)used loosely here to
            # apply to UDP host/port/proto combos and any other protocol that
            # may be supported in the future.
            self.port_fwd_table_lock.acquire()
            try:
                if pkey in self.port_fwd_table:
                    self.logger.debug('Condition 3 satisfied')
                    self.logger.debug(' = FOUND portfwd key entry: ' + pkey)
                    new_sport = self.port_fwd_table[pkey]
                    hdr = self.mangle_srcport(pkt, hdr, proto_name, hdr.data.sport, new_sport)
                    pkt.set_payload(hdr.pack())
                else:
                    self.logger.debug(' ! NO SUCH portfwd key entry: ' + pkey)
            finally:
                self.port_fwd_table_lock.release()

            self.logger.debug('Condition 1 test')
            # Condition 1: If the remote IP address is foreign to this system,
            # then redirect it to a local IP address.
            if self.localmode and (dst_ip not in self.ip_addrs[ipver]):
                self.logger.debug('Condition 1 satisfied')
                self.ip_fwd_table_lock.acquire()
                try:
                    self.ip_fwd_table[ikey] = dst_ip

                finally:
                    self.ip_fwd_table_lock.release()

                # TODO: Try 127.0.0.1, but may need this to be 192.168.x.x
                newdst = '127.0.0.1'
                hdr_modified = self.mangle_dstip(pkt, hdr, proto_name, dst_ip, newdst)

                if hdr_modified:
                    hdr = hdr_modified
                    pkt.set_payload(hdr.pack())

                # Double write for SSL decoding purposes
                self.write_pcap(hdr.pack())

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
                    if ikey in self.ip_fwd_table:
                        self.logger.debug(' - DELETING ipfwd key entry: ' + ikey)
                        del self.ip_fwd_table[ikey]
                finally:
                    self.ip_fwd_table_lock.release()

        else:
            self.logger.debug('Not handling protocol ' + str(proto))

        pkt.accept()

    def handle_incoming(self, pkt):
        """Incoming packet hook.
        
        This serves more than one purpose, so it can't be eliminated when users
        disable RedirectAllTraffic.
        
        Here's what it does:
            1.) Write unmangled packets to pcap
            2.) Dynamic port forwarding to the default listener
            3.) Write mangled packets to pcap, too
        """

        self.logger.debug('handle_incoming...')

        raw = pkt.get_payload()
        ipver = ((ord(raw[0]) & 0xf0) >> 4)
        hdr, proto = self.parse_pkt[ipver](ipver, raw)

        # Write original, unmangled packet regardless of protocol
        self.write_pcap(hdr.pack())

        proto_name = self.handled_protocols.get(proto)

        # If the datagram is carrying a protocol we handle, parse to determine
        # redirection.
        if proto_name:
            default = self.default_listener[proto_name]
            diverted_ports = self.diverted_ports.get(proto_name, [])

            src_ip = socket.inet_ntoa(hdr.src)
            sport = hdr.data.sport

            dst_ip = socket.inet_ntoa(hdr.dst)
            dport = hdr.data.dport

            # Port forwarding key based on source
            pkey = self.gen_endpoint_key(proto_name, src_ip, sport)

            # IP forwarding key based on destination
            ikey = self.gen_endpoint_key(proto_name, dst_ip, dport)

            self.logger.debug('Incoming %s %s:%s->%s:%s' % (proto_name, src_ip, sport, dst_ip, dport))

            self.logger.debug('Condition 4 test')
            # Condition 4: If the local endpoint (IP/port/proto) combo
            # corresponds to an endpoint that initiated a conversation with a
            # foreign endpoint in the past, then fix up the source IP for this
            # incoming packet with the last destination IP that was requested
            # by the endpoint.
            self.ip_fwd_table_lock.acquire()
            try:
                if self.localmode and (ikey in self.ip_fwd_table):
                    self.logger.debug('Condition 4 satisfied')
                    self.logger.debug(' = FOUND ipfwd key entry: ' + ikey)
                    new_sip = self.ip_fwd_table[ikey]
                    hdr = self.mangle_srcip(pkt, hdr, proto_name, hdr.src, new_sip)
                    pkt.set_payload(hdr.pack())
                else:
                    self.logger.debug(' ! NO SUCH ipfwd key entry: ' + ikey)
            finally:
                self.ip_fwd_table_lock.release()

            self.logger.debug('Condition 2 test')

            # Pre-condition: destination not present in port forwarding table
            # (prevent masqueraded ports responding to unbound ports from being
            # mistaken as starting a conversation with an unbound port)
            self.port_fwd_table_lock.acquire()
            found = False
            try:
                # Uses ikey (really destination endpoint key)
                found = ikey in self.port_fwd_table
            finally:
                self.port_fwd_table_lock.release()

            # Condition 2: If the packet is destined for an unbound port, then
            # redirect it to a bound port and save the old destination IP in
            # the port forwarding table keyed by the source endpoint identity.

            if (not found) and self.decide_redir_port(ipver, proto_name, default, diverted_ports, src_ip, sport, dst_ip, dport):
            # if self.decide_redir_port(ipver, proto_name, default, diverted_ports, src_ip, sport, dst_ip, dport):
                self.logger.debug('Condition 2 satisfied')
                # Record the foreign endpoint and old destination port in the
                # port forwarding table
                self.logger.debug(' + ADDING portfwd key entry: ' + pkey)
                self.port_fwd_table_lock.acquire()
                try:
                    self.port_fwd_table[pkey] = dport
                finally:
                    self.port_fwd_table_lock.release()

                hdr_modified = self.mangle_dstport(pkt, hdr, proto_name, dport, default)

                if hdr_modified:
                    hdr = hdr_modified
                    pkt.set_payload(hdr.pack())

                # Double write for SSL decoding purposes
                self.write_pcap(hdr.pack())

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
                    if pkey in self.port_fwd_table:
                        self.logger.debug(' - DELETING portfwd key entry: ' + pkey)
                        del self.port_fwd_table[pkey]
                finally:
                    self.port_fwd_table_lock.release()

        else:
            self.logger.debug('Not handling protocol ' + str(proto))

        pkt.accept()

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

    def mangle_dstip(self, pkt, hdr, proto_name, dstip, newdstip):
        """Mangle destination IP for selected outgoing packets."""
        self.logger.debug('REDIRECTING %s %s:%d->%s:%d to IP %s' %
                (proto_name, socket.inet_ntoa(hdr.src), hdr.data.sport,
                 socket.inet_ntoa(hdr.dst), hdr.data.dport, newdstip))

        hdr.dst = socket.inet_aton(newdstip)
        self._calc_csums(hdr)
        return hdr

    def mangle_srcip(self, pkt, hdr, proto_name, src_ip, new_srcip):
        """Mangle source IP for selected incoming packets."""
        self.logger.debug('MASQUERADING %s %s:%d->%s:%d from IP %s' %
                (proto_name, socket.inet_ntoa(hdr.src), hdr.data.sport,
                 socket.inet_ntoa(hdr.dst), hdr.data.dport, new_srcip))
        hdr.src = socket.inet_aton(new_srcip)
        self._calc_csums(hdr)
        return hdr

    def mangle_dstport(self, pkt, hdr, proto_name, dstport, newdstport):
        """Mangle destination port for selected incoming packets."""
        self.logger.debug('REDIRECTING %s %s:%d->%s:%d to port %d' %
            (proto_name, socket.inet_ntoa(hdr.src), hdr.data.sport,
            socket.inet_ntoa(hdr.dst), hdr.data.dport, newdstport))
        hdr.data.dport = newdstport
        self._calc_csums(hdr)
        return hdr

    def mangle_srcport(self, pkt, hdr, proto_name, srcport, newsrcport):
        """Mangle source port for selected outgoing packets."""
        self.logger.debug('MASQUERADING %s %s:%d->%s:%d from port %d' %
            (proto_name, socket.inet_ntoa(hdr.src), hdr.data.sport,
            socket.inet_ntoa(hdr.dst), hdr.data.dport, newsrcport))
        hdr.data.sport = newsrcport
        self._calc_csums(hdr)
        return hdr

    def _calc_csums(self, hdr):
        """The roundabout dance of inducing dpkt to recalculate checksums."""
        hdr.sum = 0
        hdr.data.sum = 0
        str(hdr)  # This has the side-effect of invoking dpkt.in_cksum() et al

if __name__ == '__main__':
    logging.basicConfig(format='%(message)s')
    diverterbase.test_redir_logic(Diverter)
