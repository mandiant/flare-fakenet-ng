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
from collections import namedtuple
from collections import OrderedDict


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
        # Diverter settings and filters

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

        # Parse diverter config
        self.parse_diverter_config()

        #######################################################################
        # Network verification - Implemented in OS-specific mixin

        # Check active interfaces
        if not self.check_active_ethernet_adapters():
            self.logger.warning('WARNING: No active ethernet interfaces ' +
                                'detected!')
            self.logger.warning('         Please enable a network interface.')

        # Check configured gateways
        if not self.check_gateways():
            self.logger.warning('WARNING: No gateways configured!')
            self.logger.warning('         Please configure a default ' +
                                'gateway or route in order to intercept ' +
                                'external traffic.')

        # Check configured DNS servers
        if not self.check_dns_servers():
            self.logger.warning('WARNING: No DNS servers configured!')
            self.logger.warning('         Please configure a DNS server in ' +
                                'order to allow network resolution.')

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
                    self.diverted_ports[protocol] = list()

                self.diverted_ports[protocol].append(port)

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

                    self.port_execute[protocol][port] = \
                        listener_config['executecmd'].strip()
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
            self.logger.debug('Blacklisted hosts: %s', ', '.join(
                [str(p) for p in self.getconfigval('hostblacklist')]))

        # Redirect all traffic
        self.default_listener = dict()
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

    def write_pcap(self, data):
        if self.pcap and self.pcap_lock:
            self.pcap_lock.acquire()
            try:
                self.pcap.writepkt(data)
            finally:
                self.pcap_lock.release()


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
