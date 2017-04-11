import time
import dpkt
import socket
import logging
import threading
from collections import namedtuple
from collections import OrderedDict

class DiverterBase():
    def init_base(self, diverter_config, listeners_config, ip_addrs,
                  logging_level = logging.INFO):
        self.ip_addrs = ip_addrs

        self.pcap = None
        self.pcap_lock = None
        self.dump_packets_file_prefix = 'packets'

        self.logger = logging.getLogger('Diverter')
        self.logger.setLevel(logging_level)

        self.diverter_config = diverter_config
        self.listeners_config = listeners_config

        # Local IP address
        self.external_ip = socket.gethostbyname(socket.gethostname())
        self.loopback_ip = socket.gethostbyname('localhost')

        # Sessions cache
        # NOTE: A dictionary of source ports mapped to destination address, port tuples
        self.sessions = dict()

        #######################################################################
        # Listener specific configuration
        # NOTE: All of these definitions have protocol as the first key
        #       followed by a list or another nested dict with the actual definitions

        # Diverted ports
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
        self.blacklist_ports = { 'TCP': [], 'UDP': [] }

        # Global process blacklist
        # TODO: Allow PIDs
        self.blacklist_processes = []

        # Global host blacklist
        # TODO: Allow domain resolution
        self.blacklist_hosts     = []

        # Parse diverter config
        self.parse_diverter_config()

        #######################################################################
        # Network verification - Implemented in OS-specific mixin

        # Check active interfaces
        if not self.check_active_ethernet_adapters():
            self.logger.warning('WARNING: No active ethernet interfaces detected!')
            self.logger.warning('         Please enable a network interface.')

        # Check configured gateways
        if not self.check_gateways():
            self.logger.warning('WARNING: No gateways configured!')
            self.logger.warning('         Please configure a default gateway or route in order to intercept external traffic.')

        # Check configured DNS servers
        if not self.check_dns_servers():
            self.logger.warning('WARNING: No DNS servers configured!')
            self.logger.warning('         Please configure a DNS server in order to allow network resolution.')

        # OS-specific Diverters must initialize e.g. WinDivert,
        # libnetfilter_queue, pf/alf, etc.

    def parse_listeners_config(self, listeners_config):

        #######################################################################
        # Populate diverter ports and process filters from the configuration
        for listener_name, listener_config in listeners_config.iteritems():

            if 'port' in listener_config:

                port = int(listener_config['port'])

                if not 'protocol' in listener_config:
                    self.logger.error('ERROR: Protocol not defined for listener %s', listener_name)
                    sys.exit(1)

                protocol = listener_config['protocol'].upper()

                if not protocol in ['TCP', 'UDP']:
                    self.logger.error('ERROR: Invalid protocol %s for listener %s', protocol, listener_name)
                    sys.exit(1)

                if not protocol in self.diverted_ports:
                    self.diverted_ports[protocol] = list()

                self.diverted_ports[protocol].append(port)

                ###############################################################
                # Process filtering configuration
                if 'processwhitelist' in listener_config and 'processblacklist' in listener_config:
                    self.logger.error('ERROR: Listener can\'t have both process whitelist and blacklist.')
                    sys.exit(1)

                elif 'processwhitelist' in listener_config:
                    
                    self.logger.debug('Process whitelist:')

                    if not protocol in self.port_process_whitelist:
                        self.port_process_whitelist[protocol] = dict()

                    self.port_process_whitelist[protocol][port] = [process.strip() for process in listener_config['processwhitelist'].split(',')]

                    for port in self.port_process_whitelist[protocol]:
                        self.logger.debug(' Port: %d (%s) Processes: %s', port, protocol, ', '.join(self.port_process_whitelist[protocol][port]))

                elif 'processblacklist' in listener_config:
                    self.logger.debug('Process blacklist:')

                    if not protocol in self.port_process_blacklist:
                        self.port_process_blacklist[protocol] = dict()

                    self.port_process_blacklist[protocol][port] = [process.strip() for process in listener_config['processblacklist'].split(',')]

                    for port in self.port_process_blacklist[protocol]:
                        self.logger.debug(' Port: %d (%s) Processes: %s', port, protocol, ', '.join(self.port_process_blacklist[protocol][port]))

                ###############################################################
                # Host filtering configuration
                if 'hostwhitelist' in listener_config and 'hostblacklist' in listener_config:
                    self.logger.error('ERROR: Listener can\'t have both host whitelist and blacklist.')
                    sys.exit(1)

                elif 'hostwhitelist' in listener_config:
                    
                    self.logger.debug('Host whitelist:')

                    if not protocol in self.port_host_whitelist:
                        self.port_host_whitelist[protocol] = dict()

                    self.port_host_whitelist[protocol][port] = [host.strip() for host in listener_config['hostwhitelist'].split(',')]

                    for port in self.port_host_whitelist[protocol]:
                        self.logger.debug(' Port: %d (%s) Hosts: %s', port, protocol, ', '.join(self.port_host_whitelist[protocol][port]))

                elif 'hostblacklist' in listener_config:
                    self.logger.debug('Host blacklist:')

                    if not protocol in self.port_host_blacklist:
                        self.port_host_blacklist[protocol] = dict()

                    self.port_host_blacklist[protocol][port] = [host.strip() for host in listener_config['hostblacklist'].split(',')]

                    for port in self.port_host_blacklist[protocol]:
                        self.logger.debug(' Port: %d (%s) Hosts: %s', port, protocol, ', '.join(self.port_host_blacklist[protocol][port]))

                ###############################################################
                # Execute command configuration
                if 'executecmd' in listener_config:

                    if not protocol in self.port_execute:
                        self.port_execute[protocol] = dict()

                    self.port_execute[protocol][port] = listener_config['executecmd'].strip()
                    self.logger.debug('Port %d (%s) ExecuteCmd: %s', port, protocol, self.port_execute[protocol][port] )

    def parse_diverter_config(self):

        if self.diverter_config.get('dumppackets') and self.diverter_config['dumppackets'].lower() == 'yes':
            pcap_filename = '%s_%s.pcap' % (self.diverter_config.get('dumppacketsfileprefix', 'packets'), time.strftime('%Y%m%d_%H%M%S'))
            self.logger.info('Capturing traffic to %s', pcap_filename)
            self.pcap = dpkt.pcap.Writer(open(pcap_filename, 'wb'), linktype=dpkt.pcap.DLT_RAW)
            self.pcap_lock = threading.Lock()

        # Do not redirect blacklisted processes
        if self.diverter_config.get('processblacklist') != None:
            self.blacklist_processes = [process.strip() for process in self.diverter_config.get('processblacklist').split(',')]
            self.logger.debug('Blacklisted processes: %s', ', '.join([str(p) for p in self.blacklist_processes]))

        # Do not redirect blacklisted hosts
        if self.diverter_config.get('hostblacklist') != None:
            self.blacklist_hosts = [host.strip() for host in self.diverter_config.get('hostblacklist').split(',')]
            self.logger.debug('Blacklisted hosts: %s', ', '.join([str(p) for p in self.blacklist_hosts]))

        # Redirect all traffic
        self.default_listener = dict()
        if self.diverter_config.get('redirectalltraffic') and self.diverter_config['redirectalltraffic'].lower() == 'yes':
            # TODO: Refactor WinDivert cruft
            self.filter = "outbound and ip and (icmp or tcp or udp)"

            if self.diverter_config.get('defaulttcplistener') == None:
                self.logger.error('ERROR: No default TCP listener specified in the configuration.')
                sys.exit(1)

            elif self.diverter_config.get('defaultudplistener') == None:
                self.logger.error('ERROR: No default UDP listener specified in the configuration.')
                sys.exit(1)

            elif not self.diverter_config.get('defaulttcplistener') in self.listeners_config:
                self.logger.error('ERROR: No configuration exists for default TCP listener %s', self.diverter_config.get('defaulttcplistener'))
                sys.exit(1)

            elif not self.diverter_config.get('defaultudplistener') in self.listeners_config:
                self.logger.error('ERROR: No configuration exists for default UDP listener %s', self.diverter_config.get('defaultudplistener'))
                sys.exit(1)

            else:
                self.default_listener['TCP'] = int( self.listeners_config[ self.diverter_config['defaulttcplistener'] ]['port'] )
                self.logger.error('Using default listener %s on port %d', self.diverter_config['defaulttcplistener'], self.default_listener['TCP'])

                self.default_listener['UDP'] = int( self.listeners_config[ self.diverter_config['defaultudplistener'] ]['port'] )
                self.logger.error('Using default listener %s on port %d', self.diverter_config['defaultudplistener'], self.default_listener['UDP'])

            # Do not redirect blacklisted TCP ports
            if self.diverter_config.get('blacklistportstcp') != None:
                self.blacklist_ports['TCP'] = [int(port.strip()) for port in self.diverter_config.get('blacklistportstcp').split(',')]
                self.logger.debug('Blacklisted TCP ports: %s', ', '.join([str(p) for p in self.blacklist_ports['TCP']]))

            # Do not redirect blacklisted UDP ports
            if self.diverter_config.get('blacklistportsudp') != None:
                self.blacklist_ports['UDP'] = [int(port.strip()) for port in self.diverter_config.get('blacklistportsudp').split(',')]
                self.logger.debug('Blacklisted UDP ports: %s', ', '.join([str(p) for p in self.blacklist_ports['UDP']]))

        # Redirect only specific traffic, build the filter dynamically
        else:
            # TODO: Refactor more WinDivert cruft
            filter_diverted_ports = list()
            
            if self.diverted_ports.get('TCP') != None:
                for tcp_port in self.diverted_ports.get('TCP'):
                    filter_diverted_ports.append("tcp.DstPort == %s" % tcp_port)
                    filter_diverted_ports.append("tcp.SrcPort == %s" % tcp_port)

            if self.diverted_ports.get('UDP') != None:
                for udp_port in self.diverted_ports.get('UDP'):
                    filter_diverted_ports.append("udp.DstPort == %s" % udp_port)
                    filter_diverted_ports.append("udp.SrcPort == %s" % udp_port)

            if len(filter_diverted_ports) > 0:
                self.filter = "outbound and ip and (icmp or %s)" % " or ".join(filter_diverted_ports)
            else:
                self.filter = "outbound and ip"

    def write_pcap(self, data):
        if self.pcap and self.pcap_lock:
            self.pcap_lock.acquire()
            try:
                self.pcap.writepkt(data)
            finally:
                self.pcap_lock.release()

def test_redir_logic(diverter_factory):
    diverter_config = dict()
    diverter_config['DumpPackets'] = 'Yes'
    diverter_config['DumpPacketsFilePrefix'] = 'packets'
    diverter_config['ModifyLocalDNS'] = 'No'
    diverter_config['StopDNSService'] = 'Yes'
    diverter_config['RedirectAllTraffic'] = 'Yes'
    diverter_config['DefaultTCPListener'] = 'RawTCPListener'
    diverter_config['DefaultUDPListener'] = 'RawUDPListener'
    diverter_config['BlackListPortsTCP'] = [139]
    diverter_config['BlackListPortsUDP'] = [67, 68, 137, 138, 1900, 5355]

    listeners_config = OrderedDict()

    listeners_config['DummyTCP'] = dict()
    listeners_config['DummyTCP']['Enabled'] = 'True'
    listeners_config['DummyTCP']['Port'] = '65535'
    listeners_config['DummyTCP']['Protocol'] = 'TCP'
    listeners_config['DummyTCP']['Listener'] = 'RawListener'
    listeners_config['DummyTCP']['UseSSL'] = 'No'
    listeners_config['DummyTCP']['Timeout'] = '10'

    listeners_config['RawTCPListener'] = dict()
    listeners_config['RawTCPListener']['Enabled'] = 'True'
    listeners_config['RawTCPListener']['Port'] = '1337'
    listeners_config['RawTCPListener']['Protocol'] = 'TCP'
    listeners_config['RawTCPListener']['Listener'] = 'RawListener'
    listeners_config['RawTCPListener']['UseSSL'] = 'No'
    listeners_config['RawTCPListener']['Timeout'] = '10'

    listeners_config['DummyUDP'] = dict()
    listeners_config['DummyUDP']['Enabled'] = 'True'
    listeners_config['DummyUDP']['Port'] = '65535'
    listeners_config['DummyUDP']['Protocol'] = 'UDP'
    listeners_config['DummyUDP']['Listener'] = 'RawListener'
    listeners_config['DummyUDP']['UseSSL'] = 'No'
    listeners_config['DummyUDP']['Timeout'] = '10'

    listeners_config['RawUDPListener'] = dict()
    listeners_config['RawUDPListener']['Enabled'] = 'True'
    listeners_config['RawUDPListener']['Port'] = '1337'
    listeners_config['RawUDPListener']['Protocol'] = 'UDP'
    listeners_config['RawUDPListener']['Listener'] = 'RawListener'
    listeners_config['RawUDPListener']['UseSSL'] = 'No'
    listeners_config['RawUDPListener']['Timeout'] = '10'

    listeners_config['HTTPListener80'] = dict()
    listeners_config['HTTPListener80']['Enabled'] = 'True'
    listeners_config['HTTPListener80']['Port'] = '80'
    listeners_config['HTTPListener80']['Protocol'] = 'TCP'
    listeners_config['HTTPListener80']['Listener'] = 'HTTPListener'
    listeners_config['HTTPListener80']['UseSSL'] = 'No'
    listeners_config['HTTPListener80']['Webroot'] = 'defaultFiles/'
    listeners_config['HTTPListener80']['Timeout'] = '10'
    listeners_config['HTTPListener80']['DumpHTTPPosts'] = 'Yes'
    listeners_config['HTTPListener80']['DumpHTTPPostsFilePrefix'] = 'http'

    ip_addrs = dict()
    ip_addrs[4] = ['192.168.19.222', '127.0.0.1']
    ip_addrs[6] = []

    div = diverter_factory(diverter_config, listeners_config, ip_addrs)
    testcase = namedtuple('testcase', ['src', 'sport', 'dst', 'dport', 'expect'])

    foreign = '192.168.19.132'
    LOCAL = '192.168.19.222'
    LOOPBACK = '127.0.0.1'
    unbound = 33333
    BOUND = 80

    bound_ports = []
    for k, v in listeners_config.iteritems():
        bound_ports.append(int(v['Port'], 10))

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
        r = div.decide_redir(4, 1337, bound_ports, tc.src, tc.sport, tc.dst, tc.dport)
        if r != tc.expect:
            print('Test case failed: %s:%d -> %s:%d expected %d got %d' %
                  (tc.src, tc.sport, tc.dst, tc.dport, tc.expect, r))
