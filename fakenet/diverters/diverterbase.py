import os
import abc
import sys
import time
import dpkt
import signal
import socket
import logging
import threading
import subprocess
from . import fnpacket
from . import fnconfig
from debuglevels import *
from collections import namedtuple
from collections import OrderedDict


class DivertParms(object):
    """Class to abstract all criteria possible out of the Windows and Linux
    diverters.

    These criteria largely derive from both the diverter state and the packet
    contents. This class is sometimes passed around alongside the packet to
    provide context wtihout loading down the fnpacket.PacketCtx with extraneous
    concepts.

    Many of these critera are only applicable if the transport layer has
    been parsed and validated.
    """

    def __init__(self, diverter, pkt):
        self.diverter = diverter
        self.pkt = pkt

    @property
    def is_loopback0(self):
        return (self.pkt.src_ip0 == self.pkt.dst_ip0 ==
                self.diverter.loopback_ip)

    @property
    def is_loopback(self):
        return self.pkt.src_ip == self.pkt.dst_ip == self.diverter.loopback_ip

    @property
    def dport_hidden_listener(self):
        """Does the destination port for the packet correspond to a hidden
        listener (i.e. should the packet be redirected to the proxy)?

        Returns:
            True if dport corresponds to hidden listener, else False
        """
        return self.diverter.listener_ports.isHidden(self.pkt.proto,
                                                     self.pkt.dport)

    @property
    def src_local(self):
        """Is the source address one of the local IPs of this system?

        Returns:
            True if local source IP, else False
        """
        return self.pkt.src_ip in self.diverters.ip_addrs[self.pkt.ipver]

    @property
    def sport_bound(self):
        """Is the source port bound by a FakeNet-NG listener?

        Returns:
            True if sport is bound by FakeNet-NG, else False
        """
        return self.diverter.listener_ports.isListener(self.pkt.proto,
                                                       self.pkt.sport)

    @property
    def dport_bound(self):
        """Is the destination port bound by a FakeNet-NG listener?

        Returns:
            True if dport is bound by FakeNet-NG, else False
        """
        return self.diverter.listener_ports.isListener(self.pkt.proto,
                                                       self.pkt.dport)

    @property
    def first_packet_new_session(self):
        """Is this the first datagram from this conversation?

        Returns:
            True if this pair of endpoints hasn't conversed before, else False
        """
        return not (self.diverter.sessions.get(self.pkt.sport) ==
                    (self.pkt.dst_ip, self.pkt.dport))


class DiverterPerOSDelegate(object):
    """Delegate class for OS-specific methods that FakeNet-NG implementors must
    override.

    TODO: The following methods may need to be combined to ensure that there is
    at least a single Ethernet interface with all valid settings (instead of,
    say, several interfaces, each with only one of the components that are
    needed to make the system work).
        check_active_ethernet_adapters
        check_ipaddresses
        check_gateways (currently only a warning)
        check_dns_servers (currently only a warning)
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def check_active_ethernet_adapters(self):
        """Check that there is at least one Ethernet interface.

        Returns:
            True if there is at least one interface, else False
        """
        pass

    @abc.abstractmethod
    def check_ipaddresses(self):
        """Check that there is at least one non-null IP address associated with
        at least one interface.

        Returns:
            True if at least one IP address, else False
        """
        pass

    @abc.abstractmethod
    def check_gateways(self):
        """Check that at least one interface has a non-NULL gateway set.

        Returns:
            True if at least one gateway, else False
        """
        pass

    @abc.abstractmethod
    def fix_gateway(self):
        """Check if there is a gateway configured on any of the Ethernet
        interfaces. If not, then locate a configured IP address and set a gw
        automatically. This is necessary for VMware's Host-Only DHCP server
        which leaves the default gateway empty.

        Returns:
            True if successful, else False
        """
        pass

    @abc.abstractmethod
    def check_dns_servers(self):
        """Check that a DNS server is set.

        Returns:
            True if a DNS server is set, else False
        """
        pass

    @abc.abstractmethod
    def fix_dns(self):
        """Check if there is a DNS server on any of the Ethernet interfaces. If
        not, then locate configured IP address and set a DNS server
        automatically.

        Returns:
            True if successful, else False
        """
        pass

    @abc.abstractmethod
    def get_pid_comm(self, pkt):
        """Get the PID and process name by IP/port info.

        NOTE: the term "comm" is short for "command" and comes from the Linux
        term for process name within task_struct and displayed in ps.

        Args:
            pkt: A fnpacket.PacketCtx or derived object

        Returns:
            Tuple of length 2, containing:
                (pid, comm)
            If the pid or comm cannot be discerned, the corresponding member of
            the tuple will be None.
        """
        pass

    @abc.abstractmethod
    def getNewDestinationIp(self, src_ip):
        """Get IP to redirect to after a redirection decision has been made.

        This is OS-specific due to varying empirical results on Windows and
        Linux, and may be subject to change.

        On Windows, and possibly other operating systems, simply redirecting
        external packets to the loopback address will cause the packets not to
        be routable, so it is necessary to choose an external interface IP in
        some cases.

        Contrarywise, the Linux FTP tests will fail if all redirections are not
        routed to 127.0.0.1.

        Args:
            src_ip: A str of the source IP address represented in ASCII

        Returns:
            A str of the destination IP address represented in ASCII that the
            packet should be redirected to.
        """
        pass


class ListenerAlreadyBoundThere(Exception):
    pass


class ListenerBlackWhiteList(Exception):
    pass


class ListenerMeta(object):
    """Info about each listener.

    Makes hidden listeners explicit. Organizes process and host black/white
    lists and ExecuteCmd format strings.

    Mutators are here for building listener metadata before adding it to the
    group. Accessors are in ListenerPorts for querying the collection for
    listeners and their attributes.
    """
    def __init__(self, proto, port, hidden=False):
        self.proto = proto
        self.port = port
        self.hidden = hidden
        self.proc_bl = None
        self.proc_wl = None
        self.host_bl = None
        self.host_wl = None
        self.cmd_template = None

    def _splitBlackWhiteList(self, configtext):
        """Return list from comma-separated config line."""
        return [item.strip() for item in configtext.split(',')]

    def _validateBlackWhite(self):
        """Validate that only a black or a white list of either type (host or
        process) is configured.

        Side-effect:
            Raises ListenerBlackWhiteList if invalid
        """
        msg = None
        fmt = 'Cannot specify both %s blacklist and whitelist for port %d'
        if self.proc_wl and self.proc_bl:
            msg = fmt % ('process', self.port)
            self.proc_wl = self.proc_bl = None
        elif self.host_wl and self.host_bl:
            msg = fmt % ('host', self.port)
            self.host_wl = self.host_bl = None
        if msg:
            raise ListenerBlackWhiteList(msg)

    def setProcessWhitelist(self, configtext):
        self.proc_wl = self._splitBlackWhiteList(configtext)
        self._validateBlackWhite()

    def setProcessBlacklist(self, configtext):
        self.proc_bl = self._splitBlackWhiteList(configtext)
        self._validateBlackWhite()

    def setHostWhitelist(self, configtext):
        self.host_wl = self._splitBlackWhiteList(configtext)
        self._validateBlackWhite()

    def setHostBlacklist(self, configtext):
        self.host_bl = self._splitBlackWhiteList(configtext)
        self._validateBlackWhite()

    def setExecuteCmd(self, configtext):
        self.cmd_template = configtext


class ListenerPorts(object):
    """Collection of listeners with convenience accessors.

    Previously, FakeNet-NG had several parallel dictionaries associated with
    listener settings and lots of code like this:
        1.) Does this dictionary have a 'TCP' key?
        2.) Oh, yeah? Well, is this port in the dictionary under 'TCP'?
        3.) Ah, great! Now I can ask my question. Is there an ExecuteCmd for
            this port?

    At a cost of having to add a bit of code and a few more comment lines, This
    class takes care of the checks and turns queries like this into one-liners
    like this one:
        cmd = obj.getExecuteCmd('TCP', 80) # Returns None if not applicable
    """

    def __init__(self):
        """Initialize dictionary of dictionaries:
            protocol name => dict
                portno => ListenerMeta
        """
        self.protos = {}

    def addListener(self, listener):
        """Add a ListenerMeta under the corresponding protocol and port."""
        proto = listener.proto
        port = listener.port

        if not proto in self.protos:
            self.protos[proto] = {}

        if port in self.protos[proto]:
            raise ListenerAlreadyBoundThere(
                'Listener already bound to %s port %s' % (proto, port))

        self.protos[proto][port] = listener

    def getListenerMeta(self, proto, port):
        if proto in self.protos:
            return self.protos[proto].get(port)

    def isListener(self, proto, port):
        """Is this port associated with a listener?"""
        return bool(self.getListenerMeta(proto, port))

    def isHidden(self, proto, port):
        """Is this port associated with a listener that is hidden?"""
        listener = self.getListenerMeta(proto, port)
        return listener.hidden if listener else False

    def getPortList(self, proto):
        if proto in self.protos:
            return self.protos[proto].keys()
        return []

    def intersectsWithPorts(self, proto, ports):
        """Check if ports intersect with bound listener ports.

        Convenience method for checking whether source or destination port are
        bound to a FakeNet-NG listener.
        """
        return set(ports).intersection(self.getPortList(proto))

    def getExecuteCmd(self, proto, port):
        """Get the ExecuteCmd format string specified by the operator.

        Args:
            proto: The protocol name
            port: The port number

        Returns:
            The format string if applicable
            None, otherwise
        """
        listener = self.getListenerMeta(proto, port)
        if listener:
            return listener.cmd_template

    def _isWhiteListMiss(self, thing, whitelist):
        """Check if thing is NOT in whitelist.

        Args:
            thing: thing to check whitelist for
            whitelist: list of entries

        Returns:
            True if thing is in whitelist
            False otherwise, or if there is no whitelist
        """
        if not whitelist:
            return False
        return not (thing in whitelist)

    def _isBlackListHit(self, thing, blacklist):
        """Check if thing is in blacklist.

        Args:
            thing: thing to check blacklist for
            blacklist: list of entries

        Returns:
            True if thing is in blacklist
            False otherwise, or if there is no blacklist
        """
        if not blacklist:
            return False
        return (thing in blacklist)

    def isProcessWhiteListMiss(self, proto, port, proc):
        """Check if proc is OUTSIDE the process WHITElist for a port.

        Args:
            proto: The protocol name
            port: The port number
            proc: The process name

        Returns:
            False if no listener on this port
            Return value of _isWhiteListMiss otherwise
        """
        listener = self.getListenerMeta(proto, port)
        if not listener:
            return False
        return self._isWhiteListMiss(proc, listener.proc_wl)

    def isProcessBlackListHit(self, proto, port, proc):
        """Check if proc is IN the process BLACKlist for a port.

        Args:
            proto: The protocol name
            port: The port number
            proc: The process name

        Returns:
            False if no listener on this port
            Return value of _isBlackListHit otherwise
        """
        listener = self.getListenerMeta(proto, port)
        if not listener:
            return False
        return self._isBlackListHit(proc, listener.proc_bl)

    def isHostWhiteListMiss(self, proto, port, host):
        """Check if host is OUTSIDE the process WHITElist for a port.

        Args:
            proto: The protocol name
            port: The port number
            host: The process name

        Returns:
            False if no listener on this port
            Return value of _isWhiteListMiss otherwise
        """
        listener = self.getListenerMeta(proto, port)
        if not listener:
            return False
        return self._isWhiteListMiss(host, listener.host_wl)

    def isHostBlackListHit(self, proto, port, host):
        """Check if host is IN the process BLACKlist for a port.

        Args:
            proto: The protocol name
            port: The port number
            host: The process name

        Returns:
            False if no listener on this port
            Return value of _isBlackListHit otherwise
        """
        listener = self.getListenerMeta(proto, port)
        if not listener:
            return False
        return self._isBlackListHit(host, listener.host_bl)


class PidCommDest():
    """Helper for recognizing connections that were already displayed."""
    def __init__(self, pid, comm, proto, ip, port):
        self.pid = pid
        self.comm = comm or 'program name unknown'
        self.proto = proto or 'unknown protocol'
        self.ip = ip or 'unknown IP'
        self.port = str(port) or 'port unknown/not applicable'

    def isDistinct(self, prev, bound_ips):
        """Not quite inequality.

        Requires list of bound IPs for that IP protocol version and recognizes
        when a foreign-destined packet was redirected to localhost or to an IP
        occupied by an adapter local to the system to be able to suppress
        output of these near-duplicates.
        """
        return ((not prev) or (self.pid != prev.pid) or
                (self.comm != prev.comm) or (self.port != prev.port) or
                ((self.ip != prev.ip) and (self.ip not in bound_ips)))

    def __str__(self):
        return '%s (%s) requested %s %s:%s' % (self.comm, self.pid, self.proto,
                                               self.ip, self.port)


class DiverterBase(fnconfig.Config):
    """The beating heart.

    You must implement the following methods to ride:
        startCallback()
        stopCallback()
    """

    def __init__(self, diverter_config, listeners_config, ip_addrs,
                 logging_level=logging.INFO):
        """Initialize the DiverterBase.

        TODO: Replace the sys.exit() calls from this function with exceptions
        or some other mechanism appropriate for allowing the user of this class
        to programmatically detect and handle these cases in their own way.
        This may entail moving configuration parsing to a method with a return
        value, or modifying fakenet.py to handle Diverter exceptions.

        Args:
            diverter_config: A dict of [Diverter] config section
            listeners_config: A dict of listener configuration sections
            ip_addrs: dictionary keyed by integers 4 and 6, with each element
                being a list and each list member being a str that is an ASCII
                representation of an IP address that is associated with a local
                interface on this system.
            logging_level: Optional integer logging level such as logging.DEBUG

        Returns:
            None
        """
        # For fine-grained control of subclass debug output. Does not control
        # debug output from DiverterBase. To see DiverterBase debug output,
        # pass logging.DEBUG as the logging_level argument to init_base.
        self.pdebug_level = 0
        self.pdebug_labels = dict()

        # Override in Windows implementation
        self.running_on_windows = False

        self.pid = os.getpid()

        self.ip_addrs = ip_addrs

        self.pcap = None
        self.pcap_filename = ''
        self.pcap_lock = None

        self.logger = logging.getLogger('Diverter')
        self.logger.setLevel(logging_level)

        # Rate limiting for displaying pid/comm/proto/IP/port
        self.last_conn = None

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

        # Ports bound by FakeNet-NG listeners
        self.listener_ports = ListenerPorts()

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

        slists = ['DebugLevel', ]
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

        #######################################################################
        # Network verification - Implemented in OS-specific mixin

        # Check active interfaces
        if not self.check_active_ethernet_adapters():
            self.logger.critical('ERROR: No active ethernet interfaces '
                                 'detected!')
            self.logger.critical('         Please enable a network interface.')
            sys.exit(1)

        # Check configured ip addresses
        if not self.check_ipaddresses():
            self.logger.critical('ERROR: No interface had IP address '
                                 'configured!')
            self.logger.critical('         Please configure an IP address on '
                                 'network interface.')
            sys.exit(1)

        # Check configured gateways
        gw_ok = self.check_gateways()
        if not gw_ok:
            self.logger.warning('WARNING: No gateways configured!')
            if self.is_set('fixgateway'):
                gw_ok = self.fix_gateway()
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

    def start(self):
        """This method currently only serves the purpose of codifying what must
        be implemented on a given OS to bring FakeNet-NG to that OS.

        Further refactoring should be done to unify network interface checks,
        gateway and DNS configuration, etc. into this method while calling out
        to the already-defined (and potentially some yet-to-be-defined)
        abstract methods that handle the real OS-specific stuff.
        """
        self.logger.debug('Starting...')
        return self.startCallback()

    def stop(self):
        self.logger.info('Stopping...')
        return self.stopCallback()

    @abc.abstractmethod
    def startCallback(self):
        """Initiate packet processing and return immediately.

        Generally, install hooks/filters and start one or more threads to
        siphon packet events.

        Returns:
            True if successful, else False
        """
        pass

    @abc.abstractmethod
    def stopCallback(self):
        """Terminate packet processing.

        Generally set a flag to tell the thread to stop, join with the thread,
        uninstall hooks, and change network settings back to normal.

        Returns:
            True if successful, else False
        """
        pass

    def set_debug_level(self, lvl, labels={}):
        """Enable debug output if necessary, set the debug output level, and
        maintain a reference to the dictionary of labels to print when a given
        logging level is encountered.

        Args:
            lvl: An int mask of all debug logging levels
            labels: A dict of int => str assigning names to each debug level

        Returns:
            None
        """
        if lvl:
            self.logger.setLevel(logging.DEBUG)

        self.pdebug_level = lvl

        self.pdebug_labels = labels

    def pdebug(self, lvl, s):
        """Log only the debug trace messages that have been enabled via
        set_debug_level.

        Args:
            lvl: An int indicating the debug level of this message
            s: The mssage

        Returns:
            None
        """
        if self.pdebug_level & lvl:
            label = self.pdebug_labels.get(lvl)
            prefix = '[' + label + '] ' if label else '[some component] '
            self.logger.debug(prefix + str(s))

    def check_privileged(self):
        """UNIXy and Windows-oriented check for superuser privileges.

        Returns:
            True if superuser, else False
        """
        try:
            privileged = (os.getuid() == 0)
        except AttributeError:
            privileged = (ctypes.windll.shell32.IsUserAnAdmin() != 0)

        return privileged

    def parse_listeners_config(self, listeners_config):
        """Parse listener config sections.

        TODO: Replace the sys.exit() calls from this function with exceptions
        or some other mechanism appropriate for allowing the user of this class
        to programmatically detect and handle these cases in their own way.
        This may entail modifying fakenet.py.

        Args:
            listeners_config: A dict of listener configuration sections

        Returns:
            None
        """

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

                listener = ListenerMeta(protocol, port, hidden)

                ###############################################################
                # Process filtering configuration
                if ('processwhitelist' in listener_config and
                        'processblacklist' in listener_config):
                    self.logger.error('ERROR: Listener can\'t have both ' +
                                      'process whitelist and blacklist.')
                    sys.exit(1)

                elif 'processwhitelist' in listener_config:

                    self.logger.debug('Process whitelist:')

                    whitelist = listener_config['processwhitelist']
                    listener.setProcessWhitelist(whitelist)

                    # for port in self.port_process_whitelist[protocol]:
                    #     self.logger.debug(' Port: %d (%s) Processes: %s',
                    #                       port, protocol, ', '.join(
                    #         self.port_process_whitelist[protocol][port]))

                elif 'processblacklist' in listener_config:
                    self.logger.debug('Process blacklist:')

                    blacklist = listener_config['processblacklist']
                    listener.setProcessBlacklist(blacklist)

                    # for port in self.port_process_blacklist[protocol]:
                    #     self.logger.debug(' Port: %d (%s) Processes: %s',
                    #                       port, protocol, ', '.join(
                    #         self.port_process_blacklist[protocol][port]))

                ###############################################################
                # Host filtering configuration
                if ('hostwhitelist' in listener_config and
                        'hostblacklist' in listener_config):
                    self.logger.error('ERROR: Listener can\'t have both ' +
                                      'host whitelist and blacklist.')
                    sys.exit(1)

                elif 'hostwhitelist' in listener_config:
                    self.logger.debug('Host whitelist:')
                    host_whitelist = listener_config['hostwhitelist']
                    listener.setHostWhitelist(host_whitelist)

                    # for port in self.port_host_whitelist[protocol]:
                    #     self.logger.debug(' Port: %d (%s) Hosts: %s', port,
                    #                       protocol, ', '.join(
                    #         self.port_host_whitelist[protocol][port]))

                elif 'hostblacklist' in listener_config:
                    self.logger.debug('Host blacklist:')
                    host_blacklist = listener_config['hostblacklist']
                    listener.setHostBlacklist(host_blacklist)

                    # for port in self.port_host_blacklist[protocol]:
                    #     self.logger.debug(' Port: %d (%s) Hosts: %s', port,
                    #                       protocol, ', '.join(
                    #         self.port_host_blacklist[protocol][port]))

                # Listener metadata is now configured, add it to the dictionary
                self.listener_ports.addListener(listener)

                ###############################################################
                # Execute command configuration
                if 'executecmd' in listener_config:
                    template = listener_config['executecmd'].strip()

                    # Would prefer not to get into the middle of a debug
                    # session and learn that a typo has ruined the day, so we
                    # test beforehand to make sure all the user-specified
                    # insertion strings are valid.
                    test = self._build_cmd(template, 0, 'test', '1.2.3.4',
                                           12345, '4.3.2.1', port)
                    if not test:
                        self.logger.error(('Terminating due to incorrectly ' +
                                          'configured ExecuteCmd for ' +
                                          'listener %s') % (listener_name))
                        sys.exit(1)

                    listener.setExecuteCmd(template)

                    self.logger.debug('Port %d (%s) ExecuteCmd: %s', port,
                                      protocol,
                                      template)

    def build_cmd(self, pkt, pid, comm):
        """Retrieve the ExecuteCmd directive if applicable and build the
        command to execute.

        Args:
           pkt: An fnpacket.PacketCtx or derived object
           pid: Process ID associated with the packet
           comm: Process name (command) that sent the packet

        Returns:
            A str that is the resultant command to execute
        """
        cmd = None

        template = self.listener_ports.getExecuteCmd(pkt.proto, pkt.dport)
        if template:
            cmd = self._build_cmd(template, pid, comm, pkt.src_ip, pkt.sport,
                                  pkt.dst_ip, pkt.dport)

        return cmd

    def _build_cmd(self, tmpl, pid, comm, src_ip, sport, dst_ip, dport):
        """Build a command based on the template specified in an ExecuteCmd
        config directive, applying the parameters as needed.

        Accepts individual arguments instead of an fnpacket.PacketCtx so that
        the Diverter can test any ExecuteCmd directives at configuration time
        without having to synthesize a fnpacket.PacketCtx or construct a
        NamedTuple to satisfy the requirement for such an argument.

        Args:
            tmpl: A str containing the body of the ExecuteCmd config directive
            pid: Process ID associated with the packet
            comm: Process name (command) that sent the packet
            src_ip: The source IP address that originated the packet
            sport: The source port that originated the packet
            dst_ip: The destination IP that the packet was directed at
            dport: The destination port that the packet was directed at

        Returns:
            A str that is the resultant command to execute
        """
        cmd = None

        try:
            cmd = tmpl.format(
                pid=str(pid),
                procname=str(comm),
                src_addr=str(src_ip),
                src_port=str(sport),
                dst_addr=str(dst_ip),
                dst_port=str(dport))
        except KeyError as e:
            self.logger.error(('Failed to build ExecuteCmd for port %d due ' +
                              'to erroneous format key: %s') %
                              (dport, e.message))

        return cmd

    def execute_detached(self, execute_cmd):
        """OS-agnostic asynchronous subprocess creation.

        Executes the process with the appropriate subprocess.Popen parameters
        for UNIXy or Windows platforms to isolate the process from FakeNet-NG
        to prevent it from being interrupted by termination of FakeNet-NG,
        Ctrl-C, etc.

        Args:
            execute_cmd: A str that is the command to execute

        Side-effects:
            Creates the specified process.

        Returns:
            Success => an int that is the pid of the new process
            Failure => None
        """
        DETACHED_PROCESS = 0x00000008
        cflags = DETACHED_PROCESS if self.running_on_windows else 0
        cfds = False if self.running_on_windows else True
        shl = False if self.running_on_windows else True

        def ign_sigint():
            # Prevent KeyboardInterrupt in FakeNet-NG's console from
            # terminating child processes
            signal.signal(signal.SIGINT, signal.SIG_IGN)

        preexec = None if self.running_on_windows else ign_sigint

        try:
            pid = subprocess.Popen(execute_cmd, creationflags=cflags,
                                   shell=shl,
                                   close_fds=cfds,
                                   preexec_fn=preexec).pid
        except Exception as e:
            self.logger.error('Exception of type %s' % (str(type(e))))
            self.logger.error('Error: Failed to execute command: %s',
                              execute_cmd)
            self.logger.error('       %s', e)
        else:
            return pid

    def parse_diverter_config(self):
        """Parse [Diverter] config section.

        Args: N/A

        Side-effects:
            Diverter members (whitelists, pcap, etc.) initialized.

        Returns:
            None
        """
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

            # Adjust previously assumed mode if operator specifies MultiHost
            if self.network_mode.lower() == 'multihost':
                self.single_host_mode = False

        if (self.getconfigval('processwhitelist') and
                self.getconfigval('processblacklist')):
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

            elif not (self.getconfigval('defaulttcplistener').lower() in
                      self.listeners_config):
                self.logger.error('ERROR: No configuration exists for ' +
                                  'default TCP listener %s',
                                  self.getconfigval('defaulttcplistener'))
                sys.exit(1)

            elif not (self.getconfigval('defaultudplistener').lower() in
                      self.listeners_config):
                self.logger.error('ERROR: No configuration exists for ' +
                                  'default UDP listener %s',
                                  self.getconfigval('defaultudplistener'))
                sys.exit(1)

            else:
                default_listener = self.getconfigval('defaulttcplistener').lower()
                default_port = self.listeners_config[default_listener]['port']
                self.default_listener['TCP'] = int(default_port)
                self.logger.debug('Using default listener %s on port %d',
                                  self.getconfigval('defaulttcplistener').lower(),
                                  self.default_listener['TCP'])

                default_listener = self.getconfigval('defaultudplistener').lower()
                default_port = self.listeners_config[default_listener]['port']
                self.default_listener['UDP'] = int(default_port)
                self.logger.debug('Using default listener %s on port %d',
                                  self.getconfigval('defaultudplistener').lower(),
                                  self.default_listener['UDP'])

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
        """Writes a packet to the pcap.

        Args:
            pkt: A fnpacket.PacketCtx or derived object

        Returns:
            None

        Side-effects:
            Calls dpkt.pcap.Writer.writekpt to persist the octets
        """
        if self.pcap and self.pcap_lock:
            with self.pcap_lock:
                mangled = 'mangled' if pkt.mangled else 'initial'
                self.pdebug(DPCAP, 'Writing %s packet %s' %
                            (mangled, pkt.hdrToStr2()))
                self.pcap.writepkt(pkt.octets)

    def handle_pkt(self, pkt, callbacks3, callbacks4):
        """Generic packet hook.

        Applies FakeNet-NG decision-making to packet, deferring as necessary to
        callbacks.

        Args:
            pkt: A fnpacket.PacketCtx child class
            callbacks3: Layer 3 (network) callbacks
            callbacks4: Layer 4 (network) callbacks

        Side-effects:
            1.) Unconditionally Write unmangled packet to pcap
            2.) Call layer 3 (network) callbacks...
            3.) Call layer 4 (transport) callbacks...
            4.) If the packet headers have been modified, double-write the
                mangled packet to the pcap for SSL decoding purposes

        The caller is responsible for checking if the packet was mangled,
        updating the contents of the datagram with the network hooking specific
        to their OS, and accepting/transmitting the final packet.

        Params
        ------
        pkt: fnpacket.PacketCtx object
        callbacks3: Array of L3 (network) callbacks
        callbacks4: Array of L4 (transport) callbacks

        Side-effects:
            Mangles pkt as necessary

        Returns:
            None
        """

        # 1: Unconditionally write unmangled packet to pcap
        self.write_pcap(pkt)

        no_further_processing = False

        if pkt.ipver is None:
            self.logger.warning('%s: Failed to parse IP packet' % (pkt.label))
        else:
            self.pdebug(DGENPKT, '%s %s' % (pkt.label, pkt.hdrToStr()))

            crit = DivertParms(self, pkt)

            # fnpacket has parsed all that can be parsed, so
            pid, comm = self.get_pid_comm(pkt)
            if self.pdebug_level & DGENPKTV:
                logline = self.formatPkt(pkt, pid, comm)
                self.pdebug(DGENPKTV, logline)

            elif pid and (pid != self.pid) and crit.first_packet_new_session:
                pc = PidCommDest(pid, comm, pkt.proto, pkt.dst_ip0, pkt.dport0)
                if pc.isDistinct(self.last_conn, self.ip_addrs[pkt.ipver]):
                    self.last_conn = pc
                    self.logger.info('%s' % (str(pc)))

            # 2: Call layer 3 (network) callbacks
            for cb in callbacks3:
                # These debug outputs are useful for figuring out which
                # callback is responsible for an exception that was masked by
                # python-netfilterqueue's global callback.
                self.pdebug(DCB, 'Calling %s' % (cb))

                cb(crit, pkt)

                self.pdebug(DCB, '%s finished' % (cb))

            if pkt.proto:

                if len(callbacks4):
                    # Windows Diverter has always allowed loopback packets to
                    # fall where they may. This behavior now applies to all
                    # Diverters.
                    if crit.is_loopback:
                        self.logger.debug('Ignoring loopback packet')
                        self.logger.debug('  %s:%d -> %s:%d', pkt.src_ip,
                                          pkt.sport, pkt.dst_ip, pkt.dport)
                        no_further_processing = True

                    # 3: Layer 4 (Transport layer) callbacks
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

        # 4: Double write mangled packets to represent changes made by
        # FakeNet-NG while still allowing SSL decoding with the old packets
        if pkt.mangled:
            self.write_pcap(pkt)

    def formatPkt(self, pkt, pid, comm):
        """Format a packet analysis log line for DGENPKTV.

        Args:
            pkt: A fnpacket.PacketCtx or derived object
            pid: Process ID associated with the packet
            comm: Process executable name

        Returns:
            A str containing the log line
        """
        logline = ''

        if pkt.proto == 'UDP':
            fmt = '| {label} {proto} | {pid:>6} | {comm:<8} | {src:>15}:{sport:<5} | {dst:>15}:{dport:<5} | {length:>5} | {flags:<11} | {seqack:<35} |'
            logline = fmt.format(
                label=pkt.label,
                proto=pkt.proto,
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

        elif pkt.proto == 'TCP':
            tcp = pkt._hdr.data

            sa = 'Seq=%d, Ack=%d' % (tcp.seq, tcp.ack)

            f = []
            if (tcp.flags & dpkt.tcp.TH_RST) != 0:
                f.append('RST')
            if (tcp.flags & dpkt.tcp.TH_SYN) != 0:
                f.append('SYN')
            if (tcp.flags & dpkt.tcp.TH_ACK) != 0:
                f.append('ACK')
            if (tcp.flags & dpkt.tcp.TH_FIN) != 0:
                f.append('FIN')
            if (tcp.flags & dpkt.tcp.TH_PUSH) != 0:
                f.append('PSH')

            fmt = '| {label} {proto} | {pid:>6} | {comm:<8} | {src:>15}:{sport:<5} | {dst:>15}:{dport:<5} | {length:>5} | {flags:<11} | {seqack:<35} |'
            logline = fmt.format(
                label=pkt.label,
                proto=pkt.proto,
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
        else:
            fmt = '| {label} {proto} | {pid:>6} | {comm:<8} | {src:>15}:{sport:<5} | {dst:>15}:{dport:<5} | {length:>5} | {flags:<11} | {seqack:<35} |'
            logline = fmt.format(
                label=pkt.label,
                proto='UNK',
                pid=pid,
                comm=comm,
                src=str(pkt.src_ip),
                sport=str(pkt.sport),
                dst=str(pkt.dst_ip),
                dport=str(pkt.dport),
                length=len(pkt),
                flags='',
                seqack='',
                )
        return logline

    def check_should_ignore(self, pkt, pid, comm):
        """Indicate whether a packet should be passed without mangling.

        Checks whether the packet matches black and whitelists, or whether it
        signifies an FTP Active Mode connection.

        Args:
            pkt: A fnpacket.PacketCtx or derived object
            pid: Process ID associated with the packet
            comm: Process executable name

        Returns:
            True if the packet should be left alone, else False.
        """

        src_ip = pkt.src_ip0
        sport = pkt.sport0
        dst_ip = pkt.dst_ip0
        dport = pkt.dport0

        if not self.is_set('redirectalltraffic'):
            self.pdebug(DIGN, 'Ignoring %s packet %s' %
                        (pkt.proto, pkt.hdrToStr()))
            return True

        # SingleHost mode checks
        if self.single_host_mode:
            if comm:
                # Check process blacklist
                if comm in self.blacklist_processes:
                    self.pdebug(DIGN, ('Ignoring %s packet from process %s ' +
                                'in the process blacklist.') % (pkt.proto,
                                comm))
                    self.pdebug(DIGN, '  %s' %
                                (pkt.hdrToStr()))
                    return True

                # Check process whitelist
                elif (len(self.whitelist_processes) and (comm not in
                      self.whitelist_processes)):
                    self.pdebug(DIGN, ('Ignoring %s packet from process %s ' +
                                'not in the process whitelist.') % (pkt.proto,
                                comm))
                    self.pdebug(DIGN, '  %s' %
                                (pkt.hdrToStr()))
                    return True

                # Check per-listener blacklisted process list
                elif self.listener_ports.isProcessBlackListHit(
                        pkt.proto, dport, comm):
                    self.pdebug(DIGN, ('Ignoring %s request packet from ' +
                                'process %s in the listener process ' +
                                'blacklist.') % (pkt.proto, comm))
                    self.pdebug(DIGN, '  %s' %
                                (pkt.hdrToStr()))
                    return True

                # Check per-listener whitelisted process list
                elif self.listener_ports.isProcessWhiteListMiss(
                        pkt.proto, dport, comm):
                    self.pdebug(DIGN, ('Ignoring %s request packet from ' +
                                'process %s not in the listener process ' +
                                'whitelist.') % (pkt.proto, comm))
                    self.pdebug(DIGN, '  %s' %
                                (pkt.hdrToStr()))
                    return True

        # MultiHost mode checks
        else:
            pass  # None as of yet

        # Checks independent of mode

        # Forwarding blacklisted port
        if pkt.proto:
            if set(self.blacklist_ports[pkt.proto]).intersection([sport, dport]):
                self.pdebug(DIGN, 'Forwarding blacklisted port %s packet:' %
                            (pkt.proto))
                self.pdebug(DIGN, '  %s' % (pkt.hdrToStr()))
                return True

        # Check host blacklist
        global_host_blacklist = self.getconfigval('hostblacklist')
        if global_host_blacklist and dst_ip in global_host_blacklist:
            self.pdebug(DIGN, ('Ignoring %s packet to %s in the host ' +
                        'blacklist.') % (str(pkt.proto), dst_ip))
            self.pdebug(DIGN, '  %s' % (pkt.hdrToStr()))
            self.logger.error('IGN: host blacklist match')
            return True

        # Check the port host whitelist
        if self.listener_ports.isHostWhiteListMiss(pkt.proto, dport, dst_ip):
            self.pdebug(DIGN, ('Ignoring %s request packet to %s not in ' +
                        'the listener host whitelist.') % (pkt.proto,
                        dst_ip))
            self.pdebug(DIGN, '  %s' % (pkt.hdrToStr()))
            return True

        # Check the port host blacklist
        if self.listener_ports.isHostBlackListHit(pkt.proto, dport, dst_ip):
            self.pdebug(DIGN, ('Ignoring %s request packet to %s in the ' +
                        'listener host blacklist.') % (pkt.proto, dst_ip))
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
                (not self.listener_ports.intersectsWithPorts(pkt.proto, [sport, dport]))
                ):

                self.pdebug(DIGN | DFTP, 'Listener initiated %s connection' %
                            (pkt.proto))
                self.pdebug(DIGN | DFTP, '  %s' % (pkt.hdrToStr()))
                self.pdebug(DIGN | DFTP, '  Blacklisting port %d' % (sport))
                self.blacklist_ports[pkt.proto].append(sport)

                return True

        return False

    def check_log_icmp(self, crit, pkt):
        """Log an ICMP packet if the header was parsed as ICMP.

        Args:
            crit: A DivertParms object
            pkt: An fnpacket.PacketCtx or derived object

        Returns:
            None
        """
        if pkt.is_icmp:
            self.logger.info('ICMP type %d code %d %s' % (
                pkt.icmp_type, pkt.icmp_code, pkt.hdrToStr()))

    def getOriginalDestPort(self, orig_src_ip, orig_src_port, proto):
        """Return original destination port, or None if it was not redirected.

        The proxy listener uses this method to obtain and provide port
        information to listeners in the taste() callback as an extra hint as to
        whether the traffic may be appropriate for parsing by that listener.

        Args:
            orig_src_ip: A str that is the ASCII representation of the peer IP
            orig_src_port: An int that is the source port of the peer

        Returns:
            The original destination port if the packet was redirected
            None, otherwise
        """

        orig_src_key = fnpacket.PacketCtx.gen_endpoint_key(proto, orig_src_ip,
                                                           orig_src_port)
        with self.port_fwd_table_lock:
            return self.port_fwd_table.get(orig_src_key)

    def maybe_redir_ip(self, crit, pkt, pid, comm):
        """Conditionally redirect foreign destination IPs to localhost.

        On Linux, this is used only under SingleHost mode.

        Args:
            crit: DivertParms object
            pkt: fnpacket.PacketCtx or derived object
            pid: int process ID associated with the packet
            comm: Process name (command) that sent the packet

        Side-effects:
            May mangle the packet by modifying the destination IP to point to a
            loopback or external interface IP local to the system where
            FakeNet-NG is running.

        Returns:
            None
        """
        if self.check_should_ignore(pkt, pid, comm):
            return

        self.pdebug(DIPNAT, 'Condition 1 test')
        # Condition 1: If the remote IP address is foreign to this system,
        # then redirect it to a local IP address.
        if self.single_host_mode and (pkt.dst_ip not in self.ip_addrs[pkt.ipver]):
            self.pdebug(DIPNAT, 'Condition 1 satisfied')
            with self.ip_fwd_table_lock:
                self.ip_fwd_table[pkt.skey] = pkt.dst_ip

            newdst = self.getNewDestinationIp(pkt.src_ip)

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

            with self.ip_fwd_table_lock:
                if pkt.skey in self.ip_fwd_table:
                    self.pdebug(DIPNAT, ' - DELETING ipfwd key entry: %s' %
                                (pkt.skey))
                    del self.ip_fwd_table[pkt.skey]

    def maybe_fixup_srcip(self, crit, pkt, pid, comm):
        """Conditionally fix up the source IP address if the remote endpoint
        had their connection IP-forwarded.

        Check is based on whether the remote endpoint corresponds to a key in
        the IP forwarding table.

        Args:
            crit: DivertParms object
            pkt: fnpacket.PacketCtx or derived object
            pid: int process ID associated with the packet
            comm: Process name (command) that sent the packet

        Side-effects:
            May mangle the packet by modifying the source IP to reflect the
            original destination IP that was overwritten by maybe_redir_ip.

        Returns:
            None
        """
        # Condition 4: If the local endpoint (IP/port/proto) combo
        # corresponds to an endpoint that initiated a conversation with a
        # foreign endpoint in the past, then fix up the source IP for this
        # incoming packet with the last destination IP that was requested
        # by the endpoint.
        self.pdebug(DIPNAT, "Condition 4 test: was remote endpoint IP fwd'd?")
        with self.ip_fwd_table_lock:
            if self.single_host_mode and (pkt.dkey in self.ip_fwd_table):
                self.pdebug(DIPNAT, 'Condition 4 satisfied')
                self.pdebug(DIPNAT, ' = FOUND ipfwd key entry: ' + pkt.dkey)
                new_srcip = self.ip_fwd_table[pkt.dkey]
                self.pdebug(DIPNAT, 'MASQUERADING %s from IP %s' %
                            (pkt.hdrToStr(), new_srcip))
                pkt.src_ip = new_srcip
            else:
                self.pdebug(DIPNAT, ' ! NO SUCH ipfwd key entry: ' + pkt.dkey)

    def maybe_redir_port(self, crit, pkt, pid, comm):
        """Conditionally send packets to the default listener for this proto.

        Args:
            crit: DivertParms object
            pkt: fnpacket.PacketCtx or derived object
            pid: int process ID associated with the packet
            comm: Process name (command) that sent the packet

        Side-effects:
            May mangle the packet by modifying the destination port to point to
            the default listener.

        Returns:
            None
        """
        # Pre-condition 1: there must be a default listener for this protocol
        default = self.default_listener.get(pkt.proto)
        if not default:
            return

        # Pre-condition 2: destination must not be present in port forwarding
        # table (prevents masqueraded ports responding to unbound ports from
        # being mistaken as starting a conversation with an unbound port).
        with self.port_fwd_table_lock:
            # Uses dkey to cross-reference
            if pkt.dkey in self.port_fwd_table:
                return

        # Proxy-related check: is the dport bound by a listener that is hidden?
        dport_hidden_listener = crit.dport_hidden_listener

        # Condition 2: If the packet is destined for an unbound port, then
        # redirect it to a bound port and save the old destination IP in
        # the port forwarding table keyed by the source endpoint identity.

        bound_ports = self.listener_ports.getPortList(pkt.proto)
        if dport_hidden_listener or self.decide_redir_port(pkt, bound_ports):
            self.pdebug(DDPFV, 'Condition 2 satisfied: Packet destined for '
                        'unbound port or hidden listener')

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
            with self.ignore_table_lock:
                if ((pkt.dkey in self.ignore_table) and
                        (self.ignore_table[pkt.dkey] == pkt.sport)):
                    # This is a reply (e.g. a TCP RST) from the
                    # non-port-forwarded server that the non-port-forwarded
                    # client was trying to talk to. Leave it alone.
                    return

            if self.check_should_ignore(pkt, pid, comm):
                with self.ignore_table_lock:
                    self.ignore_table[pkt.skey] = pkt.dport
                return

            # Record the foreign endpoint and old destination port in the port
            # forwarding table
            self.pdebug(DDPFV, ' + ADDING portfwd key entry: ' + pkt.skey)
            with self.port_fwd_table_lock:
                self.port_fwd_table[pkt.skey] = pkt.dport

            self.pdebug(DDPF, 'Redirecting %s to go to port %d' %
                        (pkt.hdrToStr(), default))
            pkt.dport = default

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

            # Execute command if applicable
            self.maybeExecuteCmd(pkt, pid, comm)

    def maybe_fixup_sport(self, crit, pkt, pid, comm):
        """Conditionally fix up source port if the remote endpoint had their
        connection port-forwarded to the default listener.

        Check is based on whether the remote endpoint corresponds to a key in
        the port forwarding table.

        Side-effects:
            May mangle the packet by modifying the source port to masquerade
            traffic coming from the default listener to look as if it is coming
            from the port that the client originally requested.

        Returns:
            None
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

        with self.port_fwd_table_lock:
            new_sport = self.port_fwd_table.get(pkt.dkey)

        if new_sport:
            self.pdebug(DDPFV, 'Condition 3 satisfied: must fix up ' +
                        'source port')
            self.pdebug(DDPFV, ' = FOUND portfwd key entry: ' + pkt.dkey)
            self.pdebug(DDPF, 'MASQUERADING %s to come from port %d' %
                              (pkt.hdrToStr(), new_sport))
            pkt.sport = new_sport
        else:
            self.pdebug(DDPFV, ' ! NO SUCH portfwd key entry: ' + pkt.dkey)

        return pkt.hdr if pkt.mangled else None

    def delete_stale_port_fwd_key(self, skey):
        with self.port_fwd_table_lock:
            if skey in self.port_fwd_table:
                self.pdebug(DDPFV, ' - DELETING portfwd key entry: ' + skey)
                del self.port_fwd_table[skey]

    def decide_redir_port(self, pkt, bound_ports):
        """Decide whether to redirect a port.

        Optimized logic derived by truth table + k-map. See docs/internals.md
        for details.

        Args:
            pkt: fnpacket.PacketCtx or derived object
            bound_ports: Set of ports that are bound for this protocol

        Returns:
            True if the packet must be redirected to the default listener
            False otherwise
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
                        (str(pkt.sport), ['un', ''][c]))
            self.pdebug(DDPFV, 'dport %s (%sbound)' %
                        (str(pkt.dport), ['un', ''][d]))

            # Convenience function: binary representation of a bool
            def bn(x):
                return '1' if x else '0'  # Bool -> binary

            self.pdebug(DDPFV, 'abcd = ' + bn(a) + bn(b) + bn(c) + bn(d))

        return (not a and not d) or (not c and not d)

    def addSession(self, pkt):
        """Add a connection to the sessions hash table.

        Args:
            pkt: fnpacket.PacketCtx or derived object

        Returns:
            None
        """
        self.sessions[pkt.sport] = (pkt.dst_ip, pkt.dport)

    def maybeExecuteCmd(self, pkt, pid, comm):
        """Execute any ExecuteCmd associated with this port/listener.

        Args:
            pkt: fnpacket.PacketCtx or derived object
            pid: int process ID associated with the packet
            comm: Process name (command) that sent the packet

        Returns:
            None
        """
        if not pid:
            return

        execCmd = self.build_cmd(pkt, pid, comm)
        if execCmd:
            self.logger.info('Executing command: %s' % (execCmd))
            self.execute_detached(execCmd)

