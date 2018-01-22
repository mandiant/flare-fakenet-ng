
from scapy.all import *

import os
import sys
import dpkt
import time
import socket
import logging
import traceback
import threading
import subprocess
import subprocess as sp
import netfilterqueue

from collections import namedtuple
from netfilterqueue import NetfilterQueue

from diverters.linux.utils import *
from diverters.linux import utils as lutils
from diverters.linux.packet_handler import PacketHandler
from diverters.linux.nfqueue import make_nfqueue

from diverters.monitor import make_monitor

from diverters.mangler import make_mangler

from diverters import constants
from diverters import DiverterBase
from diverters import condition


def make_diverter(dconf, lconf, ip_addrs, loglevel):
    config = {
        'diverter_config': dconf,
        'listeners_config': lconf,
        'log_level': loglevel,
        'ip_addrs': ip_addrs,
    }
    diverter = Diverter(config)
    if not diverter.initialize():
        return None
    return diverter

class Diverter(DiverterBase):

    def __init__(self, config):
        super(Diverter, self).__init__(config)
        self._current_iptables_rules = None
        self._old_dns = None

        self.pdebug_level = 0
        self.pdebug_labels = dict()
        self.pid = os.getpid()
        self.ip_addrs = self.config.get('ip_addrs', list())

        self.pcap = None
        self.pcap_filename = ''
        self.pcap_lock = None

        # Local IP address
        self.external_ip = socket.gethostbyname(socket.gethostname())
        self.loopback_ip = socket.gethostbyname('localhost')

        # Sessions cache
        # NOTE: A dictionary of source ports mapped to destination address,
        # port tuples
        self.sessions = dict()

        #######################################################################
        # Listener specific configuration
        # NOTE: All of these definitions have protocol as the first key
        #       followed by a list or another nested dict with the actual
        #       definitions

        # Diverted ports
        # TODO: a more meaningful name might be BOUND ports indicating ports
        # that FakeNet-NG has bound to with a listener
        self.diverted_ports = dict()

        # Listener Port Process filtering
        # TODO: Allow PIDs
        self.port_process_whitelist = dict()
        self.port_process_blacklist = dict()

        # Listener Port Host filtering
        # TODO: Allow domain name resolution
        self.port_host_whitelist = dict()
        self.port_host_blacklist = dict()

        # Execute command list
        self.port_execute = dict()

        # Intercept filter
        self.filter = None

        # Default TCP/UDP listeners
        self.default_listener = dict()

        # Global TCP/UDP port blacklist
        self.blacklist_ports = {'TCP': [], 'UDP': []}

        # Global process blacklist
        # TODO: Allow PIDs
        self.blacklist_processes = []
        self.whitelist_processes = []

        # Global host blacklist
        # TODO: Allow domain resolution
        self.blacklist_hosts = []

    def initialize(self):
        if not super(Diverter, self).initialize():
            return False
        
        # Check active interfaces
        if not lutils.check_active_ethernet_adapters():
            self.logger.warning('WARNING: No active ethernet interfaces ' +
                                'detected!')
            self.logger.warning('         Please enable a network interface.')

        # Check configured gateways
        if not lutils.check_gateways():
            self.logger.warning('WARNING: No gateways configured!')
            self.logger.warning('         Please configure a default ' +
                                'gateway or route in order to intercept ' +
                                'external traffic.')

        # Check configured DNS servers
        if not lutils.check_dns_servers():
            self.logger.warning('WARNING: No DNS servers configured!')
            self.logger.warning('         Please configure a DNS server in ' +
                                'order to allow network resolution.')


        if not self._parse_listeners_config():
            return False

        if not self._parse_diverter_config():
            return False

        # String list configuration item that is specific to the Linux
        # Diverter, will not be parsed by DiverterBase, and needs to be
        # accessed as an array in the future.
        # slists = ['linuxredirectnonlocal', 'DebugLevel']
        # self.reconfigure(portlists=[], stringlists=slists)

        if not self.check_privileged():
            self.logger.error('The Linux Diverter requires administrative ' +
                              'privileges')
            return False

        dbg_lvl = 0
        dconfig = self.config.get('diverter_config')        

        mode = dconfig.get('networkmode', 'singlehost').lower()
        available_modes = ['singlehost', 'multihost']
        if mode is None or mode not in available_modes:
            self.logger.error('Network mode must be one of %s ' % (available_modes,))
            return False
        self.single_host_mode = True if mode == 'singlehost' else False
        if self.single_host_mode and not self._confirm_experimental():
            return False
        self.logger.info('Running in %s mode' % (mode))

        self.parse_pkt = dict()
        self.parse_pkt[4] = lutils.parse_nfqueue_ipv4_packet
        self.parse_pkt[6] = lutils.parse_nfqueue_ipv6_packet

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

        # XXX: dirty!

        self.__incoming_conditions = self.__make_incoming_conditions()      
        if self.__incoming_conditions is None:
            self.logger.error('Failed to make incoming conditions')
            return False
        __incoming_mangler_config = {
            'ip_forward_table': self.ip_fwd_table,
            'type': 'SrcIpFwdMangler',
        }
        self.__incoming_mangler = make_mangler(__incoming_mangler_config)
        if self.__incoming_mangler is None:
            self.logger.error('Failed to make incoming mangler')
            return False
        return True
    

    def __make_incoming_conditions(self):
        """
        Make a bunch of conditions to filter incoming data based on local 
        listeners:
        1. If there is a session going on: ignore it.
        2. If dst ip is not me and dport has a listener: fix dst ip it
        3. If dst ip is not me and dport does not have a listener: ignore, for now
        """

        lconf = self.listeners_config
        cb = lutils.get_procname_from_ip_packet
        is_divert = True
        logger = self.logger
        conds = condition.make_forwarder_conditions(lconf, cb, is_divert, logger)
        return [conds]

    def start(self):
        self.logger.info('Starting Linux Diverter...')

        self._current_iptables_rules = lutils.capture_iptables(self.logger)
        if self._current_iptables_rules == None:
            self.logger.error('Failed to capture current iptables rules')
            return False

        if self.diverter_config.get('linuxflushiptables', False):
            lutils.flush_iptables()
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

        self.logger.debug('<DNFQUEUE> Discovering the next '
                          '%d available NFQUEUE numbers' % (nhooks,))
        qnos = lutils.get_next_nfqueue_numbers(nhooks)
        if len(qnos) != nhooks:
            self.logger.error('Could not procure a sufficient number of ' +
                              'netfilter queue numbers')
            return False

        self.logger.debug('<DNFQUEUE> Next available NFQUEUE '
                          'numbers: ' + str(qnos))
        self.logger.debug('<DNFQUEUE> Enumerating queue numbers and hook '
                          'specifications to create NFQUEUE objects')
                          
        self.nfqueues = list()
        for qno, hk in zip(qnos, callbacks):
            self.pdebug(DNFQUEUE, ('Creating NFQUEUE object for chain %s / ' +
                        'table %s / queue # %d => %s') % (hk.chain, hk.table,
                        qno, str(hk.callback)))
            q = make_nfqueue(qno, hk.chain, hk.table, hk.callback)
            if q is None:
                self.logger.error('Failed to create nfqueue')
                return False

            self.nfqueues.append(q)
            ok = q.start()
            if not ok:
                self.logger.error('Failed to start NFQUEUE for %s' % (str(q)))
                self.stop()
                return False
        
        if self.single_host_mode:
            if self.diverter_config.get('fixgateway', None):
                self.logger.info('fixing gateway')
                if not lutils.get_default_gw():
                    self.logger.info("fixing gateway")
                    lutils.set_default_gw(self.ip_addrs)

            if self.diverter_config.get('modifylocaldns', None):
                self.logger.info('modifying local DNS')
                self._old_dns = lutils.modifylocaldns_ephemeral(self.ip_addrs)
            
            cmd = self.diverter_config.get('linuxflushdnscommand', None)
            if cmd is not None:
                ret = subprocess.call(cmd.split())
                if not ret == 0:
                    self.logger.error('Failed to flush DNS cache. Local machine may use cached DNS results.')

        specified_ifaces = self.diverter_config.get('linuxredirectnonlocal', None)
        if specified_ifaces is not None:
            ok, rules = lutils.iptables_redir_nonlocal(specified_ifaces)
            # Irrespective of whether this failed, we want to add any
            # successful iptables rules to the list so that stop() will be able
            # to remove them using linux_remove_iptables_rules().
            self.rules_added += rules
            if not ok:
                self.logger.error('Failed to process LinuxRedirectNonlocal')
                self.stop()
                return False
        
        ok, rule = lutils.redir_icmp()
        if not ok:
            self.logger.error('Failed to redirect ICMP')
            self.stop()
            return False

        self.rules_added.append(rule)
        return True

    def stop(self):
        self.logger.info('Stopping Linux Diverter...')

        self.pdebug(DNFQUEUE, 'Notifying NFQUEUE objects of imminent stop')
        for q in self.nfqueues:
            q.stop_nonblocking()

        self.pdebug(DIPTBLS, 'Removing iptables rules not associated with any ' +
                    'NFQUEUE object')
        lutils.remove_iptables_rules(self.rules_added)

        for q in self.nfqueues:
            self.pdebug(DNFQUEUE, 'Stopping NFQUEUE for %s' % (str(q)))
            q.stop()

        if self.pcap:
            self.pdebug(DMISC, 'Closing pcap file %s' % (self.pcap_filename))
            self.pcap.close()  # Only after all queues are stopped

        self.logger.info('Stopped Linux Diverter')

        if self.single_host_mode and self.diverter_config.get('modifylocaldns', None):
            lutils.restore_local_dns(self._old_dns)

        lutils.restore_iptables(self._current_iptables_rules)

    def getOriginalDestPort(self, orig_src_ip, orig_src_port, proto):
        """Return original destination port, or None if it was not redirected
        """ 
        
        orig_src_key = utils.gen_endpoint_key(proto, orig_src_ip, orig_src_port)
        self.port_fwd_table_lock.acquire()
        
        try:
            if orig_src_key in self.port_fwd_table:
                return self.port_fwd_table[orig_src_key]
            
            return None
        finally:
            self.port_fwd_table_lock.release()

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

        global_host_blacklist = self.diverter_config.get('hostblacklist', None)
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
        ip_packet = utils.pack_into_ippacket(ipver, proto_name, src_ip, sport,
                                             dst_ip, dport)
        ip_packet = self.__incoming_mangler.mangle(ip_packet)
        hdr.src = socket.inet_aton(ip_packet.src)
        self._calc_csums(hdr)
        return hdr

    def _maybe_fixup_srcip(self, label, pid, comm, ipver, hdr, proto_name,
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



        self.logger.error('%s->%s' % (src_ip, dst_ip))
        # Condition 4: If the local endpoint (IP/port/proto) combo
        # corresponds to an endpoint that initiated a conversation with a
        # foreign endpoint in the past, then fix up the source IP for this
        # incoming packet with the last destination IP that was requested
        # by the endpoint.
        self.pdebug(DIPNAT, "Condition 4 test: was remote endpoint IP fwd'd?")
        self.ip_fwd_table_lock.acquire()
        try:
            if self.single_host_mode and (dkey in self.ip_fwd_table):
                self.logger.error('Condition 4 satisfied')
                self.logger.error(' = FOUND ipfwd key entry: ' + dkey)
                new_srcip = self.ip_fwd_table[dkey]
                hdr_modified = self.mangle_srcip(
                    hdr, proto_name, hdr.src, new_srcip)
            else:
                self.logger.error(' ! NO SUCH ipfwd key entry: ' + dkey)
        finally:
            self.ip_fwd_table_lock.release()
        return hdr_modified

    def maybe_redir_port(self, label, pid, comm, ipver, hdr, proto_name,
                         src_ip, sport, skey, dst_ip, dport, dkey):
        '''Nothing todo for now'''
        return None

    def _maybe_redir_port(self, label, pid, comm, ipver, hdr, proto_name,
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
        if not 'redirectalltraffic' in self.diverter_config:
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
        
        # First, check if this packet is sent from a listener/diverter
        # If so, don't redir for 'Hidden' status because it is already 
        # being forwarded from proxy listener to bound/hidden listener
        # Next, check if listener for this port is 'Hidden'. If so, we need to
        # divert it to the proxy as per the Hidden config
        if (dport in bound_ports and pid != self.pid and 
                bound_ports[dport] is True):
     
            #divert to proxy
            hdr_modified = self.mangle_dstport(hdr, proto_name, dport, default)
        
            # Record the foreign endpoint and old destination port in the port
            # forwarding table
            self.pdebug(DDPFV, ' + ADDING portfwd key entry: ' + skey)
            self.port_fwd_table_lock.acquire()
            try:
                self.port_fwd_table[skey] = dport
            finally:
                self.port_fwd_table_lock.release()

            # Record the altered port for making the ExecuteCmd decision
            dport = default

        # Condition 2: If the packet is destined for an unbound port, then
        # redirect it to a bound port and save the old destination IP in
        # the port forwarding table keyed by the source endpoint identity.

        elif self.decide_redir_port(ipver, proto_name, default, bound_ports,
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
                    utils.execute_detached(cmd, False, self.logger)

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

    def set_debug_level(self, lvl, labels={}):
        """Enable debug output if necessary and set the debug output level."""
        if lvl:
            self.logger.setLevel(logging.DEBUG)

        self.pdebug_level = lvl

        self.pdebug_labels = labels

    def pdebug(self, lvl, s):
        """Log only the debug trace messages that have been enabled."""
        if self.pdebug_level & lvl:
            label = self.pdebug_labels.get(lvl)
            prefix = '[' + label + '] ' if label else '[some component] '
            self.logger.debug(prefix + str(s))

    def check_privileged(self):
        try:
            privileged = (os.getuid() == 0)
        except AttributeError:
            privileged = (ctypes.windll.shell32.IsUserAnAdmin() != 0)

        return privileged


    def _build_cmd(self, tmpl, pid, comm, src_ip, sport, dst_ip, dport):
        cmd = None

        try:
            cmd = tmpl.format(
                pid = str(pid),
                procname = str(comm),
                src_addr = str(src_ip),
                src_port = str(sport),
                dst_addr = str(dst_ip),
                dst_port = str(dport))
        except KeyError as e:
            self.logger.error(('Failed to build ExecuteCmd for port %d due ' +
                              'to erroneous format key: %s') %
                              (dport, e.message))

        return cmd



    def build_cmd(self, proto_name, pid, comm, src_ip, sport, dst_ip, dport):
        cmd = None

        if ((proto_name in self.port_execute) and
                (dport in self.port_execute[proto_name])
           ):
            template = self.port_execute[proto_name][dport]
            cmd = self._build_cmd(template, pid, comm, src_ip, sport, dst_ip,
                                  dport)

        return cmd

    

    def write_pcap(self, data):
        if self.pcap and self.pcap_lock:
            self.pcap_lock.acquire()
            try:
                self.pcap.writepkt(data)
            finally:
                self.pcap_lock.release()

    def _calc_csums(self, hdr):
        """The roundabout dance of inducing dpkt to recalculate checksums."""
        hdr.sum = 0
        hdr.data.sum = 0
        str(hdr)  # This has the side-effect of invoking dpkt.in_cksum() et al
    

    def _confirm_experimental(self):
        while True:
            prompt = ('You acknowledge that SingleHost mode on Linux is ' +
                        'experimental and not functionally complete? ' +
                        '[Y/N] ')
            acknowledgement = raw_input(prompt)
            okay = ['y', 'yes', 'yeah', 'sure', 'okay', 'whatever']
            nope = ['n', 'no', 'nah', 'nope']
            if acknowledgement.lower() in okay:
                self.logger.info('Okay, we\'ll take it for a spin!')
                return True
            elif acknowledgement.lower() in nope:
                self.logger.error('User opted out of crowd-sourced ' +
                                    'alpha testing program ;-)')
                return False
        return False

    def _parse_listeners_config(self):
        listeners_config = self.listeners_config
        #######################################################################
        # Populate diverter ports and process filters from the configuration
        for listener_name, listener_config in listeners_config.iteritems():
            if 'port' in listener_config:
                port = int(listener_config['port'])
                hidden = listener_config.get('hidden', 'false') == 'True'
                if not 'protocol' in listener_config:
                    self.logger.error('ERROR: Protocol not defined for ' +
                                      'listener %s', listener_name)
                    return False

                protocol = listener_config['protocol'].upper()
                if not protocol in ['TCP', 'UDP']:
                    self.logger.error('ERROR: Invalid protocol %s for ' +
                                      'listener %s', protocol, listener_name)
                    return False

                # diverted_ports[protocol][port] is True if the listener is 
                # configured as 'Hidden', which means it will not receive 
                # packets unless the ProxyListener determines that the protocol
                # matches the listener
                if not protocol in self.diverted_ports:
                    self.diverted_ports[protocol] = dict()

                self.diverted_ports[protocol][port] = hidden

                ###############################################################
                # Process filtering configuration
                if 'processwhitelist' in listener_config and 'processblacklist' in listener_config:
                    self.logger.error('ERROR: Listener can\'t have both ' +
                                      'process whitelist and blacklist.')
                    return False

                elif 'processwhitelist' in listener_config:

                    self.logger.debug('Process whitelist:')

                    if not protocol in self.port_process_whitelist:
                        self.port_process_whitelist[protocol] = dict()

                    self.port_process_whitelist[protocol][port] = [
                        process.strip() for process in
                        listener_config['processwhitelist'].split(',')]

                    for port in self.port_process_whitelist[protocol]:
                        self.logger.debug(' Port: %d (%s) Processes: %s',
                                          port, protocol, ', '.join(
                            self.port_process_whitelist[protocol][port]))

                elif 'processblacklist' in listener_config:
                    self.logger.debug('Process blacklist:')

                    if not protocol in self.port_process_blacklist:
                        self.port_process_blacklist[protocol] = dict()

                    self.port_process_blacklist[protocol][port] = [
                        process.strip() for process in
                        listener_config['processblacklist'].split(',')]

                    for port in self.port_process_blacklist[protocol]:
                        self.logger.debug(' Port: %d (%s) Processes: %s',
                                          port, protocol, ', '.join(
                            self.port_process_blacklist[protocol][port]))

                ###############################################################
                # Host filtering configuration
                if 'hostwhitelist' in listener_config and 'hostblacklist' in listener_config:
                    self.logger.error('ERROR: Listener can\'t have both ' +
                                      'host whitelist and blacklist.')
                    return False

                elif 'hostwhitelist' in listener_config:

                    self.logger.debug('Host whitelist:')

                    if not protocol in self.port_host_whitelist:
                        self.port_host_whitelist[protocol] = dict()

                    self.port_host_whitelist[protocol][port] = [host.strip() 
                        for host in
                        listener_config['hostwhitelist'].split(',')]

                    for port in self.port_host_whitelist[protocol]:
                        self.logger.debug(' Port: %d (%s) Hosts: %s', port,
                                          protocol, ', '.join(
                            self.port_host_whitelist[protocol][port]))

                elif 'hostblacklist' in listener_config:
                    self.logger.debug('Host blacklist:')

                    if not protocol in self.port_host_blacklist:
                        self.port_host_blacklist[protocol] = dict()

                    self.port_host_blacklist[protocol][port] = [host.strip()
                        for host in
                        listener_config['hostblacklist'].split(',')]

                    for port in self.port_host_blacklist[protocol]:
                        self.logger.debug(' Port: %d (%s) Hosts: %s', port,
                                          protocol, ', '.join(
                            self.port_host_blacklist[protocol][port]))

                ###############################################################
                # Execute command configuration
                if 'executecmd' in listener_config:
                    template = listener_config['executecmd'].strip()

                    # Would prefer not to get into the middle of a debug
                    # session and learn that a typo has ruined the day, so we
                    # test beforehand by 
                    test = self._build_cmd(template, 0, 'test', '1.2.3.4',
                                           12345, '4.3.2.1', port)
                    if not test:
                        self.logger.error(('Terminating due to incorrectly ' +
                                          'configured ExecuteCmd for ' +
                                          'listener %s') % (listener_name))
                        sys.exit(1)

                    if not protocol in self.port_execute:
                        self.port_execute[protocol] = dict()

                    self.port_execute[protocol][port] = \
                        listener_config['executecmd'].strip()
                    self.logger.debug('Port %d (%s) ExecuteCmd: %s', port,
                                      protocol,
                                      self.port_execute[protocol][port])
        return True

    def _parse_diverter_config(self):
        dconf = self.diverter_config
        blist = dconf.get('processblacklist', None)
        wlist = dconf.get('processwhitelist', None)

        if blist is not None and wlist is not None:
            self.logger.error('ERROR: Diverter can\'t have both process '
                              'whitelist and blacklist.')
            return False


        # Do not redirect blacklisted processes
        if blist is not None:
            self.blacklist_processes = [process.strip() for process in
                                        blist.split(',')]
            self.logger.debug('Blacklisted processes: %s', ', '.join(
                [str(p) for p in self.blacklist_processes]))

        if wlist is not None:
            self.whitelist_processes = [process.strip() for process in
                                        wlist.split(',')]
            self.logger.debug('Whitelisted processes: %s', ', '.join(
                [str(p) for p in self.whitelist_processes]))

        if dconf.get('dumppackets', False):
            prefix = dconf.get('dumppacketsfileprefix', 'packets')
            self.pcap_filename = '%s_%s.pcap' % (prefix, time.strftime('%Y%m%d_%H%M%S'))
            self.logger.info('Capturing traffic to %s', self.pcap_filename)
            self.pcap = dpkt.pcap.Writer(open(self.pcap_filename, 'wb'),
                linktype=dpkt.pcap.DLT_RAW)
            self.pcap_lock = threading.Lock()            


        # Do not redirect blacklisted hosts
        '''
        if self.is_configured('hostblacklist'):
            self.logger.debug('Blacklisted hosts: %s', ', '.join(
                [str(p) for p in self.getconfigval('hostblacklist')]))
        '''

        # Redirect all traffic
        self.default_listener = dict()
        if 'redirectalltraffic' in dconf:
            tcplistener = dconf.get('defaulttcplistener', None)
            udplistener = dconf.get('defaultudplistener', None)

            if tcplistener is None:
                self.logger.error('ERROR: No default TCP listener specified ' +
                                  'in the configuration.')
                return False
            if tcplistener not in self.listeners_config:
                self.logger.error('ERROR: No configuration exists for ' +
                                  'default TCP listener %s', tcplistener)
                return False
            
            if udplistener is None:
                self.logger.error('ERROR: No default UDP listener specified ' +
                                  'in the configuration.')
                return False

            if udplistener not in self.listeners_config:
                self.logger.error('ERROR: No configuration exists for ' +
                                  'default UDP listener %s', udplistener)
                return False

        
            self.default_listener['TCP'] = int(
                self.listeners_config[tcplistener]['port'])
            self.logger.error('Using default listener %s on port %d',
                              tcplistener, self.default_listener['TCP'])

            self.default_listener['UDP'] = int(
                self.listeners_config[udplistener]['port'])
            self.logger.error('Using default listener %s on port %d',
                              udplistener, self.default_listener['UDP'])

            # Re-marshall these into a readily usable form...

            # Do not redirect blacklisted TCP ports
            tcpports_blist = dconf.get('blacklistportstcp', None)
            if tcpports_blist is not None:
                self.blacklist_ports['TCP'] = tcpports_blist
                self.logger.debug('Blacklisted TCP ports: %s', ', '.join(
                    [str(p) for p in tcpports_blist]))

            # Do not redirect blacklisted UDP ports
            udpports_blist = dconf.get('blacklistportsudp', None)
            if udpports_blist is not None:
                self.blacklist_ports['UDP'] = udpports_blist
                self.logger.debug('Blacklisted UDP ports: %s', ', '.join(
                    [str(p) for p in udpports_blist]))
        return True

if __name__ == '__main__':
    logging.basicConfig(format='%(message)s')
    diverterbase.test_redir_logic(Diverter)


