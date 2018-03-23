import os
import sys
import time
import dpkt
import signal
import socket
import logging
import fnconfig
import threading
import subprocess
import fnpacket
from debuglevels import *
from collections import namedtuple
from collections import OrderedDict

class DivertParms(object):
    """Class to abstract all criteria possible out of the respective diverters.

    Many of these critera are only applicable if the transport layer has
    been parsed and validated.

    These criteria largely derive from both the diverter state and the packet
    contents. It seems more ideal to create a friend class for DiverterBase
    than to load down the fnpacket abstraction with extraneous concepts.
    """

    def __init__(self, diverter, pkt):
        self.diverter = diverter
        self.pkt = pkt

    @property
    def is_loopback(self):
        return self.pkt.src_ip == self.pkt.dst_ip == self.diverter.loopback_ip

    @property
    def dport_hidden_listener(self):
        return self.diverter.diverted_ports.get(self.pkt.dport) is True

    @property
    def src_local(self):
        return self.pkt.src_ip in self.diverters.ip_addrs[self.pkt.ipver]

    @property
    def sport_bound(self):
        return self.pkt.sport in self.diverter.diverted_ports.get(self.pkt.proto_name)

    @property
    def dport_bound(self):
        return self.pkt.dport in self.diverter.diverted_ports.get(self.pkt.proto_name)

    @property
    def first_packet_new_session(self):
        return not (self.diverter.sessions.get(self.pkt.sport) ==
                    (self.pkt.dst_ip, self.pkt.dport))

    @property
    def win_divert_locally(self):
        return (self.diverter.diverted_ports.get(self.pkt.proto_name) and
                (not self.sport_bound) and
                (self.dport_bound or
                 self.diverter.default_listener.get(self.pkt.proto_name)))

class DiverterBase(fnconfig.Config):


    def init_base(self, diverter_config, listeners_config, ip_addrs,
                  logging_level=logging.INFO):
        # For fine-grained control of subclass debug output. Does not control
        # debug output from DiverterBase. To see DiverterBase debug output,
        # pass logging.DEBUG as the logging_level argument to init_base.
        self.pdebug_level = 0
        self.pdebug_labels = dict()

        self.pid = os.getpid()

        self.ip_addrs = ip_addrs

        self.pcap = None
        self.pcap_filename = ''
        self.pcap_lock = None

        self.logger = logging.getLogger('Diverter')
        self.logger.setLevel(logging_level)

        portlists = ['BlackListPortsTCP', 'BlackListPortsUDP']
        stringlists = ['HostBlackList']
        self.configure(diverter_config, portlists, stringlists)
        self.listeners_config = dict((k.lower(), v)
                                     for k, v in listeners_config.iteritems())

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

        # Parse listener configurations
        self.parse_listeners_config(listeners_config)

        #######################################################################
        # Diverter settings

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

        # Parse diverter config
        self.parse_diverter_config()

        #######################################################################
        # Network verification - Implemented in OS-specific mixin

        # Check active interfaces
        if not self.check_active_ethernet_adapters():
            self.logger.warning('WARNING: No active ethernet interfaces ' +
                                'detected!')
            self.logger.warning('         Please enable a network interface.')
            sys.exit(1)

        # Check configured ip addresses
        if not self.check_ipaddresses():
            self.logger.warning('ERROR: No interface had IP address configured!')
            self.logger.warning('         Please configure an IP address on a network interface.')
            sys.exit(1)

        # Check configured gateways
        gw_ok = self.check_gateways()
        if not gw_ok:
            self.logger.warning('WARNING: No gateways configured!')
            if self.is_set('fixgateway'):
                gw_ok = fix_gateway()
                if not gw_ok:
                    self.logger.warning('Cannot fix gateway')

        if not gw_ok:
            self.logger.warning('         Please configure a default ' +
                                'gateway or route in order to intercept ' +
                                'external traffic.')
            self.logger.warning('         Current interception abilities ' +
                                'are limited to local traffic.')

        # Check configured DNS servers
        dns_ok = self.check_dns_servers()
        if not dns_ok:
            self.logger.warning('WARNING: No DNS servers configured!')
            if self.is_set('fixdns'):
                dns_ok = self.fix_dns()
                if not dns_ok:
                    self.logger.warning('Cannot fix DNS')

        if not dns_ok:
            self.logger.warning('         Please configure a DNS server ' +
                                'in order to allow network resolution.')

        # OS-specific Diverters must initialize e.g. WinDivert,
        # libnetfilter_queue, pf/alf, etc.

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

    def parse_listeners_config(self, listeners_config):

        #######################################################################
        # Populate diverter ports and process filters from the configuration
        for listener_name, listener_config in listeners_config.iteritems():

            if 'port' in listener_config:

                port = int(listener_config['port'])

                hidden = (listener_config.get('hidden', 'false').lower() ==
                          'true')

                if not 'protocol' in listener_config:
                    self.logger.error('ERROR: Protocol not defined for ' +
                                      'listener %s', listener_name)
                    sys.exit(1)

                protocol = listener_config['protocol'].upper()

                if not protocol in ['TCP', 'UDP']:
                    self.logger.error('ERROR: Invalid protocol %s for ' +
                                      'listener %s', protocol, listener_name)
                    sys.exit(1)

                if not protocol in self.diverted_ports:
                    self.diverted_ports[protocol] = dict()

                # diverted_ports[protocol][port] is True if the listener is 
                # configured as 'Hidden', which means it will not receive 
                # packets unless the ProxyListener determines that the protocol
                # matches the listener
                self.diverted_ports[protocol][port] = hidden

                ###############################################################
                # Process filtering configuration
                if 'processwhitelist' in listener_config and 'processblacklist' in listener_config:
                    self.logger.error('ERROR: Listener can\'t have both ' +
                                      'process whitelist and blacklist.')
                    sys.exit(1)

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
                    sys.exit(1)

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

                    self.port_execute[protocol][port] = template
                    self.logger.debug('Port %d (%s) ExecuteCmd: %s', port,
                                      protocol,
                                      self.port_execute[protocol][port])

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

    ###########################################################################
    # Execute process and detach
    def execute_detached(self, execute_cmd, winders=False):
        """Supposedly OS-agnostic asynchronous subprocess creation.

        Written in anticipation of re-factoring diverters into a common class
        parentage.

        Not tested on Windows. Override or fix this if it does not work, for
        instance to use the Popen creationflags argument or omit the close_fds
        argument on Windows.
        """
        DETACHED_PROCESS = 0x00000008
        cflags = DETACHED_PROCESS if winders else 0
        cfds = False if winders else True
        shl = False if winders else True

        def ign_sigint():
            # Prevent KeyboardInterrupt in FakeNet-NG's console from
            # terminating child processes
            signal.signal(signal.SIGINT, signal.SIG_IGN)

        # import pdb
        # pdb.set_trace()
        try:
            pid = subprocess.Popen(execute_cmd, creationflags=cflags,
                                   shell=shl,
                                   close_fds = cfds,
                                   preexec_fn = ign_sigint).pid
        except Exception, e:
            self.logger.error('Error: Failed to execute command: %s', execute_cmd)
            self.logger.error('       %s', e)
        else:
            return pid

    def build_cmd(self, proto_name, pid, comm, src_ip, sport, dst_ip, dport):
        cmd = None

        if ((proto_name in self.port_execute) and
                (dport in self.port_execute[proto_name])
           ):
            template = self.port_execute[proto_name][dport]
            cmd = self._build_cmd(template, pid, comm, src_ip, sport, dst_ip,
                                  dport)

        return cmd

    def parse_diverter_config(self):
        # SingleHost vs MultiHost mode
        self.network_mode = 'SingleHost'  # Default
        self.single_host_mode = True
        if self.is_configured('networkmode'):
            self.network_mode = self.getconfigval('networkmode')
            available_modes = ['singlehost', 'multihost']

            # Constrain argument values
            if self.network_mode.lower() not in available_modes:
                self.logger.error('NetworkMode must be one of %s' %
                                  (available_modes))
                sys.exit(1)

            # Adjust previously assumed mode if user specifies MultiHost
            if self.network_mode.lower() == 'multihost':
                self.single_host_mode = False

        if self.getconfigval('processwhitelist') and self.getconfigval('processblacklist'):
            self.logger.error('ERROR: Diverter can\'t have both process ' +
                              'whitelist and blacklist.')
            sys.exit(1)

        if self.is_set('dumppackets'):
            self.pcap_filename = '%s_%s.pcap' % (self.getconfigval(
                'dumppacketsfileprefix', 'packets'),
                time.strftime('%Y%m%d_%H%M%S'))
            self.logger.info('Capturing traffic to %s', self.pcap_filename)
            self.pcap = dpkt.pcap.Writer(open(self.pcap_filename, 'wb'),
                linktype=dpkt.pcap.DLT_RAW)
            self.pcap_lock = threading.Lock()

        # Do not redirect blacklisted processes
        if self.is_configured('processblacklist'):
            self.blacklist_processes = [process.strip() for process in
                self.getconfigval('processblacklist').split(',')]
            self.logger.debug('Blacklisted processes: %s', ', '.join(
                [str(p) for p in self.blacklist_processes]))

        # Only redirect whitelisted processes
        if self.is_configured('processwhitelist'):
            self.whitelist_processes = [process.strip() for process in
                self.getconfigval('processwhitelist').split(',')]
            self.logger.debug('Whitelisted processes: %s', ', '.join(
                [str(p) for p in self.whitelist_processes]))

        # Do not redirect blacklisted hosts
        if self.is_configured('hostblacklist'):
            self.blacklist_hosts = self.getconfigval('hostblacklist')
            self.logger.debug('Blacklisted hosts: %s', ', '.join(
                [str(p) for p in self.getconfigval('hostblacklist')]))

        # Redirect all traffic
        self.default_listener = {'TCP': None, 'UDP': None}
        if self.is_set('redirectalltraffic'):
            if self.is_unconfigured('defaulttcplistener'):
                self.logger.error('ERROR: No default TCP listener specified ' +
                                  'in the configuration.')
                sys.exit(1)

            elif self.is_unconfigured('defaultudplistener'):
                self.logger.error('ERROR: No default UDP listener specified ' +
                                  'in the configuration.')
                sys.exit(1)

            elif not self.getconfigval('defaulttcplistener').lower() in self.listeners_config:
                self.logger.error('ERROR: No configuration exists for ' +
                                  'default TCP listener %s', self.getconfigval(
                    'defaulttcplistener'))
                sys.exit(1)

            elif not self.getconfigval('defaultudplistener').lower() in self.listeners_config:
                self.logger.error('ERROR: No configuration exists for ' +
                                  'default UDP listener %s', self.getconfigval(
                                  'defaultudplistener'))
                sys.exit(1)

            else:
                self.default_listener['TCP'] = int(
                    self.listeners_config[self.getconfigval('defaulttcplistener').lower()]['port'])
                self.logger.error('Using default listener %s on port %d', self.getconfigval(
                    'defaulttcplistener').lower(), self.default_listener['TCP'])

                self.default_listener['UDP'] = int(
                    self.listeners_config[self.getconfigval('defaultudplistener').lower()]['port'])
                self.logger.error('Using default listener %s on port %d', self.getconfigval(
                    'defaultudplistener').lower(), self.default_listener['UDP'])

            # Re-marshall these into a readily usable form...

            # Do not redirect blacklisted TCP ports
            if self.is_configured('blacklistportstcp'):
                self.blacklist_ports['TCP'] = \
                    self.getconfigval('blacklistportstcp')
                self.logger.debug('Blacklisted TCP ports: %s', ', '.join(
                    [str(p) for p in self.getconfigval('BlackListPortsTCP')]))

            # Do not redirect blacklisted UDP ports
            if self.is_configured('blacklistportsudp'):
                self.blacklist_ports['UDP'] = \
                    self.getconfigval('blacklistportsudp')
                self.logger.debug('Blacklisted UDP ports: %s', ', '.join(
                    [str(p) for p in self.getconfigval('BlackListPortsUDP')]))

    def write_pcap(self, pkt):
        if self.pcap and self.pcap_lock:
            self.pcap_lock.acquire()
            try:
                if isinstance(pkt, fnpacket.PacketCtx):
                    self.pdebug(DPCAP, 'Writing %s' % (pkt.hdrToStr2()))
                    self.pcap.writepkt(pkt.octets)
                else:
                    self.pcap.writepkt(pkt)
            finally:
                self.pcap_lock.release()

    def handle_pkt(self, pkt, callbacks3, callbacks4):
        """Generic packet hook.

        Params
        ------
        pkt: fnpacket.PacketCtx object
        callbacks3: Array of L3 callbacks
        callbacks4: Array of L4 callbacks
        Returns:
            Modified raw octets, if applicable

        1.) Common prologue:
            A.) Unconditionally Write unmangled packet to pcap
            B.) Parse IP packet
        2.) Call layer 3 (network) callbacks...
        3.) Parse higher-layer protocol (TCP, UDP) for port numbers
        4.) Call layer 4 (transport) callbacks...
        5.) If the packet headers have been modified, double-write the mangled
            packet to the pcap for SSL decoding purposes
        6.) The caller must:
            A.) Update the packet payload
            B.) Accept the packet with NetfilterQueue or whatever
        """

        # 1A: Unconditionally write unmangled packet to pcap
        self.write_pcap(pkt)

        no_further_processing = False

        if (pkt._hdr, pkt.proto) == (None, None):
            self.logger.warning('%s: Failed to parse IP packet' % (pkt.label))
        else:
            self.pdebug(DGENPKT, '%s %s' % (pkt.label, pkt.hdrToStr()))

            crit = DivertParms(self, pkt)

            # 1B: Parse IP packet

            # 2: Call layer 3 (network) callbacks
            for cb in callbacks3:
                # These debug outputs are useful for figuring out which
                # callback is responsible for an exception that was masked by
                # python-netfilterqueue's global callback.
                self.pdebug(DCB, 'Calling %s' % (cb))

                cb(crit, pkt)

                self.pdebug(DCB, '%s finished' % (cb))

            if pkt.proto_name:

                if len(callbacks4):
                    # 3: Parse higher-layer protocol
                    pid, comm = self.get_pid_comm(pkt)

                    if pkt.proto_name == 'UDP':
                        fmt = '| {label} {proto} | {pid:>6} | {comm:<8} | {src:>15}:{sport:<5} | {dst:>15}:{dport:<5} | {length:>5} | {flags:<11} | {seqack:<35} |'
                        logline = fmt.format(
                                label=pkt.label,
                                proto=pkt.proto_name,
                                pid=pid,
                                comm=comm,
                                src=pkt.src_ip,
                                sport=pkt.sport,
                                dst=pkt.dst_ip,
                                dport=pkt.dport,
                                length=len(pkt),
                                flags='',
                                seqack='',
                            )
                        self.pdebug(DGENPKTV, logline)

                    elif pkt.proto_name == 'TCP':
                        tcp = pkt._hdr.data
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
                                label=pkt.label,
                                proto=pkt.proto_name,
                                pid=pid,
                                comm=comm,
                                src=pkt.src_ip,
                                sport=pkt.sport,
                                dst=pkt.dst_ip,
                                dport=pkt.dport,
                                length=len(pkt),
                                flags=','.join(f),
                                seqack=sa,
                            )
                        self.pdebug(DGENPKTV, logline)

                    if ((not (self.pdebug_level & DGENPKTV)) and
                        pid and (pid != self.pid)):
                        self.logger.info('  pid:  %d name: %s' %
                                         (pid, comm if comm else 'Unknown'))

                    # Windows Diverter has always allowed loopback packets to
                    # fall where they may. This behavior is being ported to all
                    # Diverters.
                    if crit.is_loopback:
                        self.logger.debug('Ignoring loopback packet')
                        self.logger.debug('  %s:%d -> %s:%d', pkt.src_ip, pkt.sport, pkt.dst_ip, pkt.dport)
                        no_further_processing = True

                    # 4: Layer 4 (Transport layer) callbacks
                    if not no_further_processing:
                        for cb in callbacks4:
                            # These debug outputs are useful for figuring out
                            # which callback is responsible for an exception
                            # that was masked by python-netfilterqueue's global
                            # callback.
                            self.pdebug(DCB, 'Calling %s' % (cb))

                            cb(crit, pkt, pid, comm)

                            self.pdebug(DCB, '%s finished' % (cb))

            else:
                self.pdebug(DGENPKT, '%s: Not handling protocol %s' %
                                     (pkt.label, pkt.proto))

        if pkt.mangled:
            # 5Ai: Double write mangled packets to represent changes
            # made by FakeNet-NG while still allowing SSL decoding
            self.write_pcap(pkt)

            # 5Aii: Finalize changes with caller
            return pkt.octets

        return None

    def check_should_ignore(self, pkt, pid, comm):

        src_ip = pkt.src_ip0
        sport = pkt.sport0
        dst_ip = pkt.dst_ip0
        dport = pkt.dport0

        # SingleHost mode checks
        if self.single_host_mode:
            if comm:
                # Check process blacklist
                if comm in self.blacklist_processes:
                    self.pdebug(DIGN, ('Ignoring %s packet from process %s ' +
                                'in the process blacklist.') % (pkt.proto_name,
                                comm))
                    self.pdebug(DIGN, '  %s' %
                                (pkt.hdrToStr()))
                    return True

                # Check process whitelist
                elif (len(self.whitelist_processes) and (comm not in
                      self.whitelist_processes)):
                    self.pdebug(DIGN, ('Ignoring %s packet from process %s ' +
                                'not in the process whitelist.') % (pkt.proto_name,
                                comm))
                    self.pdebug(DIGN, '  %s' %
                                (pkt.hdrToStr()))
                    return True

                # Check per-listener blacklisted process list
                elif ((pkt.proto_name in self.port_process_blacklist) and
                        (dport in self.port_process_blacklist[pkt.proto_name])):
                    # If program DOES match blacklist
                    if comm in self.port_process_blacklist[pkt.proto_name][dport]:
                        self.pdebug(DIGN, ('Ignoring %s request packet from ' +
                                    'process %s in the listener process ' +
                                    'blacklist.') % (pkt.proto_name, comm))
                        self.pdebug(DIGN, '  %s' %
                                    (pkt.hdrToStr()))

                    return True

                # Check per-listener whitelisted process list
                elif ((pkt.proto_name in self.port_process_whitelist) and
                        (dport in self.port_process_whitelist[pkt.proto_name])):
                    # If program does NOT match whitelist
                    if not comm in self.port_process_whitelist[pkt.proto_name][dport]:
                        self.pdebug(DIGN, ('Ignoring %s request packet from ' +
                                    'process %s not in the listener process ' +
                                    'whitelist.') % (pkt.proto_name, comm))
                        self.pdebug(DIGN, '  %s' %
                                    (pkt.hdrToStr()))
                        return True

        # MultiHost mode checks
        else:
            pass  # None as of yet

        # Checks independent of mode

        # Forwarding blacklisted port
        if set(self.blacklist_ports[pkt.proto_name]).intersection([sport, dport]):
            self.pdebug(DIGN, 'Forwarding blacklisted port %s packet:' %
                        (pkt.proto_name))
            self.pdebug(DIGN, '  %s' % (pkt.hdrToStr()))
            return True

        # Check host blacklist
        global_host_blacklist = self.getconfigval('hostblacklist')
        if global_host_blacklist and dst_ip in global_host_blacklist:
            self.pdebug(DIGN, ('Ignoring %s packet to %s in the host ' +
                        'blacklist.') % (pkt.proto_name, dst_ip))
            self.pdebug(DIGN, '  %s' % (pkt.hdrToStr()))
            return True

        # Check the port host whitelist
        if ((pkt.proto_name in self.port_host_whitelist) and
                (dport in self.port_host_whitelist[pkt.proto_name])):
            # If host does NOT match whitelist
            if not dst_ip in self.port_host_whitelist[pkt.proto_name][dport]:
                self.pdebug(DIGN, ('Ignoring %s request packet to %s not in ' +
                            'the listener host whitelist.') % (pkt.proto_name,
                            dst_ip))
                self.pdebug(DIGN, '  %s' % (pkt.hdrToStr()))
                return True

        # Check the port host blacklist
        if ((pkt.proto_name in self.port_host_blacklist) and
                (dport in self.port_host_blacklist[pkt.proto_name])):
            # If host DOES match blacklist
            if dst_ip in self.port_host_blacklist[pkt.proto_name][dport]:
                self.pdebug(DIGN, ('Ignoring %s request packet to %s in the ' +
                            'listener host blacklist.') % (pkt.proto_name, dst_ip))
                self.pdebug(DIGN, '  %s' % (pkt.hdrToStr()))
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
                ((dst_ip in self.ip_addrs[pkt.ipver]) and
                (not dst_ip.startswith('127.'))) and
                ((src_ip in self.ip_addrs[pkt.ipver]) and
                (not dst_ip.startswith('127.'))) and
                (not set([sport, dport]).intersection(self.diverted_ports[pkt.proto_name]))
                ):

                self.pdebug(DIGN | DFTP, 'Listener initiated %s connection' %
                            (pkt.proto_name))
                self.pdebug(DIGN | DFTP, '  %s' % (pkt.hdrToStr()))
                self.pdebug(DIGN | DFTP, '  Blacklisting port %d' % (sport))
                self.blacklist_ports[pkt.proto_name].append(sport)

            return True

        return False

    def addSession(self, pkt):
        self.sessions[pkt.sport] = (pkt.dst_ip, pkt.dport)

def test_redir_logic(diverter_factory):
    diverter_config = dict()
    diverter_config['dumppackets'] = 'Yes'
    diverter_config['dumppacketsfileprefix'] = 'packets'
    diverter_config['modifylocaldns'] = 'No'
    diverter_config['stopdnsservice'] = 'Yes'
    diverter_config['redirectalltraffic'] = 'Yes'
    diverter_config['defaulttcplistener'] = 'RawTCPListener'
    diverter_config['defaultudplistener'] = 'RawUDPListener'
    diverter_config['blacklistportstcp'] = '139'
    diverter_config['blacklistportsudp'] = '67, 68, 137, 138, 1900, 5355'

    listeners_config = OrderedDict()

    listeners_config['dummytcp'] = dict()
    listeners_config['dummytcp']['enabled'] = 'True'
    listeners_config['dummytcp']['port'] = '65535'
    listeners_config['dummytcp']['protocol'] = 'TCP'
    listeners_config['dummytcp']['listener'] = 'RawListener'
    listeners_config['dummytcp']['usessl'] = 'No'
    listeners_config['dummytcp']['timeout'] = '10'

    listeners_config['rawtcplistener'] = dict()
    listeners_config['rawtcplistener']['enabled'] = 'True'
    listeners_config['rawtcplistener']['port'] = '1337'
    listeners_config['rawtcplistener']['protocol'] = 'TCP'
    listeners_config['rawtcplistener']['listener'] = 'RawListener'
    listeners_config['rawtcplistener']['usessl'] = 'No'
    listeners_config['rawtcplistener']['timeout'] = '10'

    listeners_config['dummyudp'] = dict()
    listeners_config['dummyudp']['enabled'] = 'True'
    listeners_config['dummyudp']['port'] = '65535'
    listeners_config['dummyudp']['protocol'] = 'UDP'
    listeners_config['dummyudp']['listener'] = 'RawListener'
    listeners_config['dummyudp']['usessl'] = 'No'
    listeners_config['dummyudp']['timeout'] = '10'

    listeners_config['rawudplistener'] = dict()
    listeners_config['rawudplistener']['enabled'] = 'True'
    listeners_config['rawudplistener']['port'] = '1337'
    listeners_config['rawudplistener']['protocol'] = 'UDP'
    listeners_config['rawudplistener']['listener'] = 'RawListener'
    listeners_config['rawudplistener']['usessl'] = 'No'
    listeners_config['rawudplistener']['timeout'] = '10'

    listeners_config['httplistener80'] = dict()
    listeners_config['httplistener80']['enabled'] = 'True'
    listeners_config['httplistener80']['port'] = '80'
    listeners_config['httplistener80']['protocol'] = 'TCP'
    listeners_config['httplistener80']['listener'] = 'HTTPListener'
    listeners_config['httplistener80']['usessl'] = 'No'
    listeners_config['httplistener80']['webroot'] = 'defaultFiles/'
    listeners_config['httplistener80']['timeout'] = '10'
    listeners_config['httplistener80']['dumphttpposts'] = 'Yes'
    listeners_config['httplistener80']['dumphttppostsfileprefix'] = 'http'

    ip_addrs = dict()
    ip_addrs[4] = ['192.168.19.222', '127.0.0.1']
    ip_addrs[6] = []

    div = diverter_factory(diverter_config, listeners_config, ip_addrs)
    testcase = namedtuple(
        'testcase', ['src', 'sport', 'dst', 'dport', 'expect'])

    foreign = '192.168.19.132'
    LOCAL = '192.168.19.222'
    LOOPBACK = '127.0.0.1'
    unbound = 33333
    BOUND = 80

    bound_ports = []
    for k, v in listeners_config.iteritems():
        bound_ports.append(int(v['port'], 10))

    testcases = [
        testcase(foreign, unbound, LOCAL, unbound, True),
        testcase(foreign, unbound, LOCAL, BOUND, False),
        testcase(foreign, BOUND, LOCAL, unbound, True),
        testcase(foreign, BOUND, LOCAL, BOUND, False),

        testcase(LOCAL, unbound, foreign, unbound, True),
        testcase(LOCAL, unbound, foreign, BOUND, False),
        testcase(LOCAL, BOUND, foreign, unbound, False),
        testcase(LOCAL, BOUND, foreign, BOUND, False),

        testcase(LOOPBACK, unbound, LOOPBACK, unbound, True),
        testcase(LOOPBACK, unbound, LOOPBACK, BOUND, False),
        testcase(LOOPBACK, BOUND, LOOPBACK, unbound, False),
        testcase(LOOPBACK, BOUND, LOOPBACK, BOUND, False),
    ]

    for tc in testcases:
        r = div.decide_redir_port(4, 'TCP', 1337, bound_ports, tc.src,
                                  tc.sport, tc.dst, tc.dport)
        if r != tc.expect:
            print('TEST CASE FAILED: %s:%d -> %s:%d expected %d got %d' %
                  (tc.src, tc.sport, tc.dst, tc.dport, tc.expect, r))
        else:
            print('Test case passed: %s:%d -> %s:%d expected %d got %d' %
                  (tc.src, tc.sport, tc.dst, tc.dport, tc.expect, r))
