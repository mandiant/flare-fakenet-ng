# Diverter for Windows implemented using WinDivert library

import logging

from pydivert.windivert import *

import socket

import os

import dpkt

import time
import threading

import platform

from winutil import *

import subprocess

class Diverter(WinUtilMixin):

    def __init__(self, diverter_config, listeners_config, logging_level = logging.INFO):

        self.logger = logging.getLogger('Diverter')
        self.logger.setLevel(logging_level)

        self.diverter_config = diverter_config
        self.listeners_config = listeners_config

        # Local IP address
        self.external_ip = socket.gethostbyname(socket.gethostname())
        self.loopback_ip = socket.gethostbyname('localhost')

        # Used for caching of DNS server names prior to changing
        self.adapters_dns_server_backup = dict()

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
        # NOTE: All relevant connections are recorded as outbound by WinDivert
        #       so additional filtering based on destination port will need to be
        #       performed in order to determine the correct traffic direction.
        self.filter = None

        # Default TCP/UDP listeners
        self.default_listener_tcp_port = None
        self.default_listener_udp_port = None

        # Global TCP/UDP port blacklist
        self.blacklist_ports_tcp = []
        self.blacklist_ports_udp = []

        # Global process blacklist
        # TODO: Allow PIDs
        self.blacklist_processes = []

        # Global host blacklist
        # TODO: Allow domain resolution
        self.blacklist_hosts     = []

        # Parse diverter config
        self.parse_diverter_config()

        #######################################################################
        # Network verification

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

        #######################################################################
        # Initialize WinDivert
        
        try:
            self.handle = WinDivert(filter=self.filter)
            self.handle.open()
        except WindowsError, e:
            if e.winerror == 5:
                self.logger.error('ERROR: Insufficient privileges to run windows diverter.')
                self.logger.error('       Please restart with Administrator privileges.')
                sys.exit(1)
            elif e.winerror == 3:
                self.logger.error('ERROR: Could not locate WinDivert DLL or one of its components.')
                self.logger.error('       Please make sure you have copied FakeNet-NG to the C: drive.')
                sys.exit(1)
            else:
                self.logger.error('ERROR: Failed to open a handle to the WinDivert driver: %s', e)
                sys.exit(1)

        # Capture packets configuration
        self.capture_flag = False
        self.dump_packets_file_prefix = "packets"
        self.pcap = None

        if self.diverter_config.get('dumppackets') and self.diverter_config['dumppackets'].lower() == 'yes':
                self.capture_flag = True
                pcap_filename = "%s_%s.pcap" % (diverter_config.get('dumppacketsfileprefix', 'packets'), time.strftime("%Y%m%d_%H%M%S"))

                self.logger.info('Capturing traffic to %s', pcap_filename)
                self.pcap = dpkt.pcap.Writer(open(pcap_filename, 'wb'), linktype=dpkt.pcap.DLT_RAW)

    ###########################################################################
    # Parse listener specific settings and filters

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

    ###########################################################################
    # Parse diverter settings and filters

    def parse_diverter_config(self):

        # Do not redirect blacklisted processes
        if self.diverter_config.get('processblacklist') != None:
            self.blacklist_processes = [process.strip() for process in self.diverter_config.get('processblacklist').split(',')]
            self.logger.debug('Blacklisted processes: %s', ', '.join([str(p) for p in self.blacklist_processes]))

        # Do not redirect blacklisted hosts
        if self.diverter_config.get('hostblacklist') != None:
            self.blacklist_hosts = [host.strip() for host in self.diverter_config.get('hostblacklist').split(',')]
            self.logger.debug('Blacklisted hosts: %s', ', '.join([str(p) for p in self.blacklist_hosts]))

        # Redirect all traffic
        if self.diverter_config.get('redirectalltraffic') and self.diverter_config['redirectalltraffic'].lower() == 'yes':
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
                self.default_listener_tcp_port = int( self.listeners_config[ self.diverter_config['defaulttcplistener'] ]['port'] )
                self.logger.error('Using default listener %s on port %d', self.diverter_config['defaulttcplistener'], self.default_listener_tcp_port)

                self.default_listener_udp_port = int( self.listeners_config[ self.diverter_config['defaultudplistener'] ]['port'] )
                self.logger.error('Using default listener %s on port %d', self.diverter_config['defaultudplistener'], self.default_listener_udp_port)

            # Do not redirect blacklisted TCP ports
            if self.diverter_config.get('blacklistportstcp') != None:
                self.blacklist_ports_tcp = [int(port.strip()) for port in self.diverter_config.get('blacklistportstcp').split(',')]
                self.logger.debug('Blacklisted TCP ports: %s', ', '.join([str(p) for p in self.blacklist_ports_tcp]))

            # Do not redirect blacklisted UDP ports
            if self.diverter_config.get('blacklistportsudp') != None:
                self.blacklist_ports_udp = [int(port.strip()) for port in self.diverter_config.get('blacklistportsudp').split(',')]
                self.logger.debug('Blacklisted UDP ports: %s', ', '.join([str(p) for p in self.blacklist_ports_udp]))

        # Redirect only specific traffic, build the filter dynamically
        else:

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

    ###########################################################################
    # Diverter controller functions

    def start(self):

        self.logger.info('Starting...')

        # Set local DNS server IP address
        if self.diverter_config.get('modifylocaldns') and self.diverter_config['modifylocaldns'].lower() == 'yes':
            self.set_dns_server(self.loopback_ip)

        # Stop DNS service
        if self.diverter_config.get('stopdnsservice') and self.diverter_config['stopdnsservice'].lower() == 'yes':
            self.stop_service_helper('Dnscache') 

        self.logger.info('Diverting ports: ')
        if self.diverted_ports.get('TCP'): self.logger.info('TCP: %s', ', '.join("%d" % port for port in self.diverted_ports['TCP']))
        if self.diverted_ports.get('UDP'): self.logger.info('UDP: %s', ', '.join("%d" % port for port in self.diverted_ports['UDP']))
        
        self.flush_dns()

        self.diverter_thread = threading.Thread(target=self.divert_thread)
        self.diverter_thread.daemon = True

        self.diverter_thread.start()

    def divert_thread(self):

        try:
            while True:
                packet = self.handle.recv()
                self.handle_packet(packet)

        # Handle errors related to shutdown process.      
        except WindowsError as e:
            if e.winerror in [4,6,995]:
                return
            else:
                raise

    def stop(self):
        self.logger.info('Stopping...')
        if self.pcap:
            self.pcap.close()

        self.handle.close()

        # Restore DNS server
        if self.diverter_config.get('modifylocaldns') and self.diverter_config['modifylocaldns'].lower() == 'yes':
            self.restore_dns_server()

        # Restart DNS service
        if self.diverter_config.get('stopdnsservice') and self.diverter_config['stopdnsservice'].lower() == 'yes':
            self.start_service_helper('Dnscache')  

        self.flush_dns()
        

    def handle_icmp_packet(self, packet):
        # Modify outgoing ICMP packet to target local Windows host which will reply to the ICMP messages.
        # HACK: Can't intercept inbound ICMP server, but still works for now.

        if not ((packet.is_loopback and packet.src_addr == self.loopback_ip and packet.dst_addr == self.loopback_ip) or \
           (packet.src_addr == self.external_ip and packet.dst_addr == self.external_ip)):

            self.logger.info('Modifying %s ICMP packet:', 'loopback' if packet.is_loopback else 'external')
            self.logger.info('  from: %s -> %s', packet.src_addr, packet.dst_addr)

            # Direct packet to the right interface IP address to avoid routing issues
            packet.dst_addr = self.loopback_ip if packet.is_loopback else self.external_ip

            self.logger.info('  to:   %s -> %s', packet.src_addr, packet.dst_addr)

        return packet

    def handle_tcp_udp_packet(self, packet, protocol, default_listener_port, blacklist_ports):

        # Meta strings
        interface_string = 'loopback' if packet.is_loopback else 'external'
        direction_string = 'inbound' if packet.is_inbound else 'outbound'

        # Protocol specific filters
        diverted_ports         = self.diverted_ports.get(protocol)
        port_process_whitelist = self.port_process_whitelist.get(protocol)
        port_process_blacklist = self.port_process_blacklist.get(protocol)
        port_host_whitelist    = self.port_host_whitelist.get(protocol)
        port_host_blacklist    = self.port_host_blacklist.get(protocol)
        port_execute           = self.port_execute.get(protocol)


        if (packet.is_loopback and packet.src_addr == self.loopback_ip and packet.dst_addr == self.loopback_ip) or \
           (packet.src_addr == self.external_ip and packet.dst_addr == self.external_ip):
            self.logger.debug('Ignoring loopback packet')

        elif packet.src_port in blacklist_ports or packet.dst_port in blacklist_ports:
            self.logger.debug('Forwarding blacklisted port %s %s %s packet:', direction_string, interface_string, protocol)
            self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

        # Check if a packet must be diverted to a local listener
        # Rules:
        # 1) Divert outbound packets only
        # 2) Make sure we are not diverting response packet based on the source port
        # 3) Make sure the destination port is a known diverted port or we have a default listener port defined
        elif diverted_ports and (packet.dst_port in diverted_ports or default_listener_port != None) and not packet.src_port in diverted_ports:

            # Find which process ID is sending the request
            conn_pid = self.get_pid_port_tcp(packet.src_port) if packet.tcp else self.get_pid_port_udp(packet.src_port)
            process_name = self.get_process_image_filename(conn_pid) if conn_pid else None

            # Check process blacklist
            if process_name and process_name in self.blacklist_processes:
                self.logger.debug('Ignoring %s %s %s request packet from process %s in the process blacklist.', direction_string, interface_string, protocol, process_name)
                self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)                

            # Check host blacklist
            elif packet.dst_addr in self.blacklist_hosts:
                self.logger.debug('Ignoring %s %s %s request packet to %s in the host blacklist.', direction_string, interface_string, protocol, packet.dst_addr)
                self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)   

            # Check the port process whitelist
            elif process_name and port_process_whitelist and \
                ((packet.dst_port in port_process_whitelist and not process_name in port_process_whitelist[packet.dst_port]) or\
                  (default_listener_port and default_listener_port in port_process_whitelist and not process_name in port_process_whitelist[default_listener_port]))  :
                self.logger.debug('Ignoring %s %s %s request packet from process %s not in the listener process whitelist.', direction_string, interface_string, protocol, process_name)
                self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

            # Check the port process blacklist
            elif process_name and port_process_blacklist and \
                ((packet.dst_port in port_process_blacklist and process_name in port_process_blacklist[packet.dst_port]) or\
                  (default_listener_port and default_listener_port in port_process_blacklist and process_name in port_process_blacklist[default_listener_port]))  :
                self.logger.debug('Ignoring %s %s %s request packet from process %s in the listener process blacklist.', direction_string, interface_string, protocol, process_name)
                self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

            # Check the port host whitelist
            elif packet.dst_addr and port_host_whitelist and \
                ((packet.dst_port in port_host_whitelist and not packet.dst_addr in port_host_whitelist[packet.dst_port]) or\
                  (default_listener_port and default_listener_port in port_host_whitelist and not packet.dst_addr in port_host_whitelist[default_listener_port]))  :
                self.logger.debug('Ignoring %s %s %s request packet to %s not in the listener host whitelist.', direction_string, interface_string, protocol, packet.dst_addr)
                self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

            # Check the port host blacklist
            elif packet.dst_addr and port_host_blacklist and \
                ((packet.dst_port in port_host_blacklist and packet.dst_addr in port_host_blacklist[packet.dst_port]) or\
                  (default_listener_port and default_listener_port in port_host_blacklist and packet.dst_addr in port_host_blacklist[default_listener_port]))  :
                self.logger.debug('Ignoring %s %s %s request packet to %s in the listener host blacklist.', direction_string, interface_string, protocol, packet.dst_addr)
                self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

            # Make sure you are not intercepting packets from one of the FakeNet listeners
            elif conn_pid and os.getpid() == conn_pid:
                self.logger.debug('Skipping %s %s %s listener packet:', direction_string, interface_string, protocol)
                self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

            # Modify the packet
            else:

                # Adjustable log level output. Used to display info level logs for first packets of the session and 
                # debug level for the rest of the communication in order to reduce log output.
                logger_level = self.logger.debug

                # First packet in a new session
                if not (packet.src_port in self.sessions and self.sessions[packet.src_port] == (packet.dst_addr, packet.dst_port)):

                    # Cache original target IP address based on source port
                    self.sessions[packet.src_port] = (packet.dst_addr, packet.dst_port)

                    # Override log level to display all information on info level
                    logger_level = self.logger.info

                    # Execute command
                    if conn_pid and port_execute and (packet.dst_port in port_execute or (default_listener_port and default_listener_port in port_execute)):


                        execute_cmd = port_execute[packet.dst_port if packet.dst_port in diverted_ports else default_listener_port].format(pid = conn_pid, 
                                                                               procname = process_name, 
                                                                               src_addr = packet.src_addr, 
                                                                               src_port = packet.src_port,
                                                                               dst_addr = packet.dst_addr,
                                                                               dst_port = packet.dst_port)

                        logger_level('Executing command: %s', execute_cmd)

                        self.execute_detached(execute_cmd)       


                logger_level('Modifying %s %s %s request packet:', direction_string, interface_string, protocol)
                logger_level('  from: %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

                # Direct packet to the right interface IP address to avoid routing issues
                packet.dst_addr = self.loopback_ip if packet.is_loopback else self.external_ip

                # Direct packet to an existing or a default listener
                packet.dst_port = packet.dst_port if packet.dst_port in diverted_ports else default_listener_port

                logger_level('  to:   %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

                if conn_pid:
                    logger_level('  pid:  %d name: %s', conn_pid, process_name if process_name else 'Unknown')


        # Restore diverted response from a local listener
        # NOTE: The response can come from a legitimate request
        elif diverted_ports and packet.src_port in diverted_ports:

            # Find which process ID is sending the request
            conn_pid = self.get_pid_port_tcp(packet.dst_port) if packet.tcp else self.get_pid_port_udp(packet.dst_port)
            process_name = self.get_process_image_filename(conn_pid)

            if not packet.dst_port in self.sessions:
                self.logger.debug('Unknown %s %s %s response packet:', direction_string, interface_string, protocol)
                self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

            # Restore original target IP address from the cache
            else:
                self.logger.debug('Modifying %s %s %s response packet:', direction_string, interface_string, protocol)
                self.logger.debug('  from: %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

                # Restore original target IP address based on destination port
                packet.src_addr, packet.src_port = self.sessions[packet.dst_port]

                self.logger.debug('  to:   %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

            if conn_pid:
                self.logger.debug('  pid:  %d name: %s', conn_pid, process_name if process_name else 'Unknown')

        else:
            self.logger.debug('Forwarding %s %s %s packet:', direction_string, interface_string, protocol)
            self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

        return packet

    def handle_packet(self, packet):

        if packet == None:
            self.logger.error('ERROR: Can\'t handle packet.')
            return

        # Preserve destination address to detect packet being diverted
        dst_addr = packet.dst_addr

        #######################################################################
        # Capture packet and store raw packet in the PCAP
        if self.capture_flag:
            self.pcap.writepkt(packet.raw.tobytes())

        ###########################################################################
        # Verify the IP packet has an additional header

        if packet.ip:

            #######################################################################
            # Handle ICMP Packets
  
            if packet.icmp:
                packet = self.handle_icmp_packet(packet)

            #######################################################################
            # Handle TCP/UDP Packets

            elif packet.tcp:
                protocol = 'TCP'
                packet = self.handle_tcp_udp_packet(packet, 
                                                    protocol, 
                                                    self.default_listener_tcp_port, 
                                                    self.blacklist_ports_tcp)

            elif packet.udp:
                protocol = 'UDP'
                packet = self.handle_tcp_udp_packet(packet,
                                                    protocol,
                                                    self.default_listener_udp_port, 
                                                    self.blacklist_ports_udp)

            else:
                self.logger.error('ERROR: Unknown packet header type.')

        #######################################################################
        # Capture modified packet and store raw packet in the PCAP
        # NOTE: While this results in potentially duplicate traffic capture, this is necessary 
        #       to properly restore TLS/SSL sessions.
        # TODO: Develop logic to record traffic before modification for both requests and
        #       responses to reduce duplicate captures.
        if self.capture_flag and (dst_addr != packet.dst_addr):
            self.pcap.writepkt(packet.raw.tobytes())

        #######################################################################
        # Attempt to send the processed packet
        try:
            self.handle.send(packet)
        except Exception, e:

            protocol = 'Unknown'

            if packet.tcp:
                protocol = 'TCP'
            elif packet.udp:
                protocol = 'UDP'
            elif packet.icmp:
                protocol = 'ICMP'

            interface_string = 'loopback' if packet.is_loopback else 'external'
            direction_string = 'inbound' if packet.is_inbound else 'outbound'

            self.logger.error('ERROR: Failed to send %s %s %s packet', direction_string, interface_string, protocol)

            if packet.src_port and packet.dst_port:
                self.logger.error('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
            else:
                self.logger.error('  %s -> %s', packet.src_addr, packet.dst_addr)

            self.logger.error('  %s', e)

def main():

    diverter_config = {'redirectalltraffic': 'no', 'defaultlistener': 'DefaultListener', 'dumppackets': 'no'}
    listeners_config = {'DefaultListener': {'port': '1337', 'protocol': 'TCP'}}

    diverter = Diverter(diverter_config, listeners_config)
    diverter.start()

    ###########################################################################
    # Run processing
    import time

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        diverter.stop()

    ###########################################################################
    # Run tests
    # TODO

if __name__ == '__main__':
    main()