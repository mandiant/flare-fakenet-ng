import sys
import dpkt
import time
import socket
import logging
import fnpacket
import traceback
import threading
import subprocess
import diverterbase
import netfilterqueue
from linutil import *
from debuglevels import *
from diverterbase import *
from collections import namedtuple
from netfilterqueue import NetfilterQueue


class LinuxPacketCtx(fnpacket.PacketCtx):
    def __init__(self, lbl, nfqpkt, local_ips):
        self.nfqpkt = nfqpkt
        raw = nfqpkt.get_payload()

        super(LinuxPacketCtx, self).__init__(lbl, raw)

        self.is_inbound0 = None
        self.is_loopback0 = None
        self.interface_string = 'unknown'
        self.direction_string = 'unknown'

        if self.ipver and self.ipver in local_ips:
            self.is_loopback0 = (self._src_ip0.startswith('127.') and
                                self._dst_ip0.startswith('127.'))
            self.is_inbound0 = ((self._src_ip0 not in local_ips[self.ipver]) and
                               (self._dst_ip0 in local_ips[self.ipver]))
            self.interface_string = 'loopback' if self.is_loopback0 else 'external'
            self.direction_string = 'inbound' if self.is_inbound0 else 'outbound'


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

        self.logger.info('Running in %s mode' % (self.network_mode))

        self.nfqueues = list()

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

        # The below callbacks are configured to be efficiently executed by the
        # handle_pkt method, incoming, and outgoing packet hooks installed by
        # the start method.

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

        if self.is_configured('linuxflushdnscommand') and self.single_host_mode:
            cmd = self.getconfigval('linuxflushdnscommand')
            ret = subprocess.call(cmd.split())
            if ret != 0:
                self.logger.error(
                'Failed to flush DNS cache. Local machine may use cached DNS results.')

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

    def getOriginalDestPort(self, orig_src_ip, orig_src_port, proto):
        """Return original destination port, or None if it was not redirected.

        Called by proxy listener.
        """ 
        
        orig_src_key = fnpacket.PacketCtx.gen_endpoint_key(proto, orig_src_ip,
                                                  orig_src_port)
        self.port_fwd_table_lock.acquire()
        
        try:
            return self.port_fwd_table.get(orig_src_key)
        finally:
            self.port_fwd_table_lock.release()

    def handle_nonlocal(self, nfqpkt):
        """Handle comms sent to IP addresses that are not bound to any adapter.

        This allows analysts to observe when malware is communicating with
        hard-coded IP addresses in MultiHost mode.
        """
        try:
            pkt = LinuxPacketCtx('handle_nonlocal', nfqpkt, self.ip_addrs)
            newraw = self.handle_pkt(pkt, self.nonlocal_net_cbs, [])
            if newraw:
                nfqpkt.set_payload(newraw)
        # Catch-all exceptions are usually bad practice, sure, but
        # python-netfilterqueue has a catch-all that will not print enough
        # information to troubleshoot with, so if there is going to be a
        # catch-all exception handler anyway, it might as well be mine so that
        # I can print out the stack trace before I lose access to this valuable
        # debugging information.
        except Exception:
            self.logger.error('Exception: %s' % (traceback.format_exc()))
            raise

        nfqpkt.accept() # NF_ACCEPT

    def handle_incoming(self, nfqpkt):
        """Incoming packet hook.

        Specific to incoming packets:
        5.) If SingleHost mode:
            a.) Conditionally fix up source IPs to support IP forwarding for
                otherwise foreign-destined packets
        4.) Conditionally mangle destination ports to implement port forwarding
            for unbound ports to point to the default listener

        No return value.
        """
        try:
            pkt = LinuxPacketCtx('handle_incoming', nfqpkt, self.ip_addrs)
            newraw = self.handle_pkt(pkt, self.incoming_net_cbs,
                                     self.incoming_trans_cbs)
            if newraw:
                nfqpkt.set_payload(newraw)
        except Exception:
            self.logger.error('Exception: %s' % (traceback.format_exc()))
            raise

        nfqpkt.accept() # NF_ACCEPT

    def handle_outgoing(self, nfqpkt):
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
        try:
            pkt = LinuxPacketCtx('handle_outgoing', nfqpkt, self.ip_addrs)
            newraw = self.handle_pkt(pkt, self.outgoing_net_cbs,
                                     self.outgoing_trans_cbs)
            if newraw:
                nfqpkt.set_payload(newraw)
        except Exception:
            self.logger.error('Exception: %s' % (traceback.format_exc()))
            raise

        nfqpkt.accept() # NF_ACCEPT

    def check_log_icmp(self, crit, pkt):
        if pkt.is_icmp:
            self.logger.info('ICMP type %d code %d %s' % (
                pkt.icmp_type, pkt.icmp_code, pkt.hdrToStr()))

        return None

    def check_log_nonlocal(self, crit, pkt):
        """Conditionally log packets having a foreign destination.

        Each foreign destination will be logged only once if the Linux
        Diverter's internal log_nonlocal_only_once flag is set. Otherwise, any
        foreign destination IP address will be logged each time it is observed.
        """

        if pkt.dst_ip not in self.ip_addrs[pkt.ipver]:
            self.pdebug(DNONLOC, 'Nonlocal %s' % pkt.hdrToStr())
            first_sighting = (pkt.dst_ip not in self.nonlocal_ips_already_seen)
            if first_sighting:
                self.nonlocal_ips_already_seen.append(pkt.dst_ip)
            # Log when a new IP is observed OR if we are not restricted to
            # logging only the first occurrence of a given nonlocal IP.
            if first_sighting or (not self.log_nonlocal_only_once):
                self.logger.info(
                    'Received nonlocal IPv%d datagram destined for %s' %
                    (pkt.ipver, pkt.dst_ip))

        return None

    def maybe_redir_ip(self, crit, pkt, pid, comm):
        """Conditionally redirect foreign destination IPs to localhost.

        Used only under SingleHost mode.

        Returns:
            None - if unmodified
            dpkt.ip.hdr - if modified
        """
        if self.check_should_ignore(pkt, pid, comm):
            return None

        self.pdebug(DIPNAT, 'Condition 1 test')
        # Condition 1: If the remote IP address is foreign to this system,
        # then redirect it to a local IP address.
        if self.single_host_mode and (pkt.dst_ip not in self.ip_addrs[pkt.ipver]):
            self.pdebug(DIPNAT, 'Condition 1 satisfied')
            self.ip_fwd_table_lock.acquire()
            try:
                self.ip_fwd_table[pkt.skey] = pkt.dst_ip

            finally:
                self.ip_fwd_table_lock.release()

            newdst = '127.0.0.1'
            self.pdebug(DIPNAT, 'REDIRECTING %s to IP %s' %
                        (pkt.hdrToStr(), newdst))
            pkt.dst_ip = newdst

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
                if pkt.skey in self.ip_fwd_table:
                    self.pdebug(DIPNAT, ' - DELETING ipfwd key entry: ' + pkt.skey)
                    del self.ip_fwd_table[pkt.skey]
            finally:
                self.ip_fwd_table_lock.release()

        return pkt.hdr if pkt.mangled else None

    def maybe_fixup_srcip(self, crit, pkt, pid, comm):
        """Conditionally fix up the source IP address if the remote endpoint
        had their connection IP-forwarded.

        Check is based on whether the remote endpoint corresponds to a key in
        the IP forwarding table.

        Returns:
            None - if unmodified
            dpkt.ip.hdr - if modified
        """
        # Condition 4: If the local endpoint (IP/port/proto) combo
        # corresponds to an endpoint that initiated a conversation with a
        # foreign endpoint in the past, then fix up the source IP for this
        # incoming packet with the last destination IP that was requested
        # by the endpoint.
        self.pdebug(DIPNAT, "Condition 4 test: was remote endpoint IP fwd'd?")
        self.ip_fwd_table_lock.acquire()
        try:
            if self.single_host_mode and (pkt.dkey in self.ip_fwd_table):
                self.pdebug(DIPNAT, 'Condition 4 satisfied')
                self.pdebug(DIPNAT, ' = FOUND ipfwd key entry: ' + pkt.dkey)
                new_srcip = self.ip_fwd_table[pkt.dkey]
                self.pdebug(DIPNAT, 'MASQUERADING %s from IP %s' %
                            (pkt.hdrToStr(), new_srcip))
                pkt.src_ip = new_srcip
            else:
                self.pdebug(DIPNAT, ' ! NO SUCH ipfwd key entry: ' + pkt.dkey)
        finally:
            self.ip_fwd_table_lock.release()

        return pkt.hdr if pkt.mangled else None

    def maybe_redir_port(self, crit, pkt, pid, comm):
        dport = pkt.dport

        # Get default listener port for this proto, or bail if none
        default = self.default_listener.get(pkt.proto_name)

        # A: Check: There is a default listener for this protocol
        if not default:
            return None

        # Pre-condition 1: RedirectAllTraffic: Yes
        # NOTE: This only applies to port redirection in the Windows Diverter;
        # IP addresses will be modified by the Windows Diverter when
        # RedirectAllTraffic is disabled. So, the Linux Diverter implementation
        # will follow suit.

        # B: Check: RedirectAllTraffic True
        if not self.is_set('redirectalltraffic'):
            self.pdebug(DIGN, 'Ignoring %s packet %s' %
                        (pkt.proto_name, pkt.hdrToStr()))
            return None

        # Pre-condition 1: destination must not be present in port forwarding
        # table (prevents masqueraded ports responding to unbound ports from
        # being mistaken as starting a conversation with an unbound port).

        # C: Check: Destination was recorded as talking to a local port that
        # was not bound and was consequently redirected to the default listener
        found = False
        self.port_fwd_table_lock.acquire()
        try:
            # Uses dkey to cross-reference
            found = pkt.dkey in self.port_fwd_table
        finally:
            self.port_fwd_table_lock.release()

        if found:
            return None

        bound_ports = self.diverted_ports.get(pkt.proto_name, [])
        
        # First, check if this packet is sent from a listener/diverter
        # If so, don't redir for 'Hidden' status because it is already 
        # being forwarded from proxy listener to bound/hidden listener
        # Next, check if listener for this port is 'Hidden'. If so, we need to
        # divert it to the proxy as per the Hidden config

        # D: Check: Proxy: dport is bound and listener is hidden
        dport_hidden_listener = bound_ports.get(dport) is True

        # Condition 2: If the packet is destined for an unbound port, then
        # redirect it to a bound port and save the old destination IP in
        # the port forwarding table keyed by the source endpoint identity.

        if dport_hidden_listener or self.decide_redir_port(pkt, bound_ports):
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
                if pkt.dkey in self.ignore_table and self.ignore_table[pkt.dkey] == pkt.sport:
                    # This is a reply (e.g. a TCP RST) from the
                    # non-port-forwarded server that the non-port-forwarded
                    # client was trying to talk to. Leave it alone.
                    return None
            finally:
                self.ignore_table_lock.release()

            if self.check_should_ignore(pkt, pid, comm):
                self.ignore_table_lock.acquire()
                try:
                    self.ignore_table[pkt.skey] = dport
                finally:
                    self.ignore_table_lock.release()
                return None

            # Record the foreign endpoint and old destination port in the port
            # forwarding table
            self.pdebug(DDPFV, ' + ADDING portfwd key entry: ' + pkt.skey)
            self.port_fwd_table_lock.acquire()
            try:
                self.port_fwd_table[pkt.skey] = dport
            finally:
                self.port_fwd_table_lock.release()

            pkt.dport = default

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

            self.delete_stale_port_fwd_key(pkt.skey)

        if crit.first_packet_new_session:
            self.addSession(pkt)

            if pid and (pkt.dst_ip in self.ip_addrs[pkt.ipver]):
                cmd = self.build_cmd(pkt.proto_name, pid, comm, pkt.src_ip,
                                     pkt.sport, pkt.dst_ip, dport)
                if cmd:
                    self.logger.info('Executing command: %s', cmd)
                    self.execute_detached(cmd)

        return pkt.hdr if pkt.mangled else None

    def maybe_fixup_sport(self, crit, pkt, pid, comm):
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
        new_sport = None
        self.pdebug(DDPFV, "Condition 3 test: was remote endpoint port fwd'd?")
        self.port_fwd_table_lock.acquire()
        try:
            new_sport = self.port_fwd_table.get(pkt.dkey)
        finally:
            self.port_fwd_table_lock.release()

        if new_sport:
            self.pdebug(DDPFV, 'Condition 3 satisfied: must fix up ' +
                        'source port')
            self.pdebug(DDPFV, ' = FOUND portfwd key entry: ' + pkt.dkey)
            self.pdebug(DDPF, 'MASQUERADING %s from port %d' %
                              (pkt.hdrToStr(), new_sport))
            pkt.sport = new_sport
        else:
            self.pdebug(DDPFV, ' ! NO SUCH portfwd key entry: ' + pkt.dkey)

        return pkt.hdr if pkt.mangled else None

    def delete_stale_port_fwd_key(self, skey):
        self.port_fwd_table_lock.acquire()
        try:
            if skey in self.port_fwd_table:
                self.pdebug(DDPFV, ' - DELETING portfwd key entry: ' + skey)
                del self.port_fwd_table[skey]
        finally:
            self.port_fwd_table_lock.release()

    def decide_redir_port(self, pkt, bound_ports):
        """Decide whether to redirect a port.

        Optimized logic derived by truth table + k-map. See docs/internals.md
        for details.
        """
        # A, B, C, D for easy manipulation; full names for readability only.
        a = src_local = (pkt.src_ip in self.ip_addrs[pkt.ipver])
        c = sport_bound = pkt.sport in (bound_ports)
        d = dport_bound = pkt.dport in (bound_ports)

        if self.pdebug_level & DDPFV:
            # Unused logic term not calculated except for debug output
            b = dst_local = (pkt.dst_ip in self.ip_addrs[pkt.ipver])

            self.pdebug(DDPFV, 'src %s (%s)' %
                        (str(pkt.src_ip), ['foreign', 'local'][a]))
            self.pdebug(DDPFV, 'dst %s (%s)' %
                        (str(pkt.dst_ip), ['foreign', 'local'][b]))
            self.pdebug(DDPFV, 'sport %s (%sbound)' %
                        (str(sport), ['un', ''][c]))
            self.pdebug(DDPFV, 'dport %s (%sbound)' %
                        (str(pkt.dport), ['un', ''][d]))

            def bn(x): return '1' if x else '0'  # Bool -> binary
            self.pdebug(DDPFV, 'abcd = ' + bn(a) + bn(b) + bn(c) + bn(d))

        return (not a and not d) or (not c and not d)

    def get_pid_comm(self, pkt):
        return self.linux_get_pid_comm_by_endpoint(pkt.ipver, pkt.proto_name,
                                                   pkt.src_ip, pkt.sport)


if __name__ == '__main__':
    logging.basicConfig(format='%(message)s')
    diverterbase.test_redir_logic(Diverter)
