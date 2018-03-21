# Diverter for Windows implemented using WinDivert library

import logging

from pydivert.windivert import *

import socket

import os
import dpkt
import fnpacket

import time
import threading
import platform

from winutil import *
from diverterbase import *

import subprocess


class WindowsPacketCtx(fnpacket.PacketCtx):
    def __init__(self, lbl, windivertpkt):
        self.windivertpkt = windivertpkt
        raw = windivertpkt.raw.tobytes()
        super(WindowsPacketCtx, self).__init__(lbl, raw)
        self.is_loopback = windivertpkt.is_loopback

    @property
    def src_ip(self): return super(self.__class__, self.__class__).src_ip

    @src_ip.setter
    def src_ip(self, new_srcip):
        super(self.__class__, self.__class__).src_ip.fset(self, new_srcip)
        self.windivertpkt.src_addr = new_srcip

    @property
    def dst_ip(self): return super(self.__class__, self.__class__).dst_ip

    @dst_ip.setter
    def dst_ip(self, new_dstip):
        super(self.__class__, self.__class__).dst_ip.fset(self, new_dstip)
        self.windivertpkt.dst_addr = new_dstip


class Diverter(DiverterBase, WinUtilMixin):

    def __init__(self, diverter_config, listeners_config, ip_addrs, logging_level = logging.INFO):

        self.init_base(diverter_config, listeners_config, ip_addrs, logging_level)

        if self.getconfigval('networkmode').lower() != 'singlehost':
            self.logger.error('Windows diverter currently only supports SingleHost mode')
            sys.exit(1)

        # Used for caching of DNS server names prior to changing
        self.adapters_dns_server_backup = dict()

        # Used to restore modified Interfaces back to DHCP
        self.adapters_dhcp_restore = list()
        self.adapters_dns_restore = list()

        # Configure external and loopback IP addresses
        self.external_ip = self.get_best_ipaddress() or self.get_ip_with_gateway() or socket.gethostbyname(socket.gethostname())

        self.logger.info("External IP: %s Loopback IP: %s" % (self.external_ip, self.loopback_ip))

        #######################################################################
        # Initialize filter and WinDivert driver

        # Build filter
        self.filter = None
        if self.is_set('redirectalltraffic'):
            self.filter = "outbound and ip and (icmp or tcp or udp)"
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

    def fix_gateway(self):
        """Check if there is a gateway configured on any of the Ethernet
        interfaces. If that's not the case, then locate configured IP address
        and set a gateway automatically. This is necessary for VMWare Host-Only
        DHCP server which leaves default gateway empty.
        """
        fixed = False

        for adapter in self.get_adapters_info():

            # Look for a DHCP interface with a set IP address but no gateway (Host-Only)
            if self.check_ipaddresses_interface(adapter) and adapter.DhcpEnabled:

                (ip_address, netmask) = next(self.get_ipaddresses_netmask(adapter))
                gw_address =  ip_address[:ip_address.rfind('.')]+'.254'

                interface_name = self.get_adapter_friendlyname(adapter.Index)

                # Don't set gateway on loopback interfaces (e.g. Npcap Loopback Adapter)
                if not "loopback" in interface_name.lower():

                    self.adapters_dhcp_restore.append(interface_name)

                    cmd_set_gw = "netsh interface ip set address name=\"%s\" static %s %s %s" % (interface_name, ip_address, netmask, gw_address)

                    # Configure gateway
                    try:
                        subprocess.check_call(cmd_set_gw, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    except subprocess.CalledProcessError, e:
                        self.logger.error("         Failed to set gateway %s on interface %s." % (gw_address, interface_name))
                    else:
                        self.logger.info("         Setting gateway %s on interface %s" % (gw_address, interface_name))
                        fixed = True

        return fixed

    def fix_dns(self):
        """Check if there is a DNS server on any of the Ethernet interfaces. If
        that's not the case, then locate configured IP address and set a DNS
        server automatically.
        """
        fixed = False

        for adapter in self.get_adapters_info():

            if self.check_ipaddresses_interface(adapter):

                ip_address = next(self.get_ipaddresses(adapter))
                dns_address = ip_address

                interface_name = self.get_adapter_friendlyname(adapter.Index)

                # Don't set DNS on loopback interfaces (e.g. Npcap Loopback Adapter)
                if not "loopback" in interface_name.lower():

                    self.adapters_dns_restore.append(interface_name)

                    cmd_set_dns = "netsh interface ip set dns name=\"%s\" static %s" % (interface_name, dns_address)

                    # Configure DNS server
                    try:
                        subprocess.check_call(cmd_set_dns, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    except subprocess.CalledProcessError, e:
                        self.logger.error("         Failed to set DNS %s on interface %s." % (dns_address, interface_name))
                    else:
                        self.logger.info("         Setting DNS %s on interface %s" % (dns_address, interface_name))
                        fixed = True

        return fixed

    def getOriginalDestPort(self, orig_src_ip, orig_src_port, proto):
        """Return original destination port, or None if it was not redirected
        """ 
        
        if orig_src_port in self.sessions:
            return self.sessions[orig_src_port]
        return None
    
    ###########################################################################
    # Parse diverter settings and filters

    def expand_ports(self, ports_list):
        ports = []
        for i in ports_list.split(','):
            if '-' not in i:
                ports.append(int(i))
            else:
                l,h = map(int, i.split('-'))
                ports+= range(l,h+1)
        return ports

    ###########################################################################
    # Diverter controller functions

    def start(self):
        self.do_new = True

        if self.do_new:
            return self.start2()
        else:
            return self.old_start()

    def stop(self):
        if self.do_new:
            return self.stop2()
        else:
            return self.old_stop()

    def start2(self):
        self.logger.info('Starting...')

        # Set local DNS server IP address
        if self.is_set('modifylocaldns'):
            self.set_dns_server(self.external_ip)

        # Stop DNS service
        if self.is_set('stopdnsservice'):
            self.stop_service_helper('Dnscache') 

        self.logger.info('Diverting ports: ')
        if self.diverted_ports.get('TCP'): self.logger.info('TCP: %s', ', '.join("%d" % port for port in self.diverted_ports['TCP']))
        if self.diverted_ports.get('UDP'): self.logger.info('UDP: %s', ', '.join("%d" % port for port in self.diverted_ports['UDP']))

        self.flush_dns()

        self.diverter_thread = threading.Thread(target=self.divert_thread2)
        self.diverter_thread.daemon = True

        self.diverter_thread.start()

    def divert_thread2(self):
        try:
            while True:
                windivertpkt = self.handle.recv()

                if windivertpkt == None:
                    self.logger.error('ERROR: Can\'t handle packet.')
                    continue

                pkt = WindowsPacketCtx('divert_thread2/handle_packet', windivertpkt)

                self.handle_packet2(windivertpkt, pkt)
        except WindowsError as e:
            if e.winerror in [4, 6, 995]:
                return
            else:
                raise

    def old_start(self):

        self.logger.info('Starting...')

        # Set local DNS server IP address
        if self.is_set('modifylocaldns'):
            self.set_dns_server(self.external_ip)

        # Stop DNS service
        if self.is_set('stopdnsservice'):
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

    def stop2(self):
        self.logger.info('Stopping...')
        if self.pcap:
            self.pcap.close()

        self.handle.close()

        # Restore DHCP adapter settings
        for interface_name in self.adapters_dhcp_restore:

            cmd_set_dhcp = "netsh interface ip set address name=\"%s\" dhcp" % interface_name

            # Restore DHCP on interface
            try:
                subprocess.check_call(cmd_set_dhcp, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError, e:
                self.logger.error("Failed to restore DHCP on interface %s." % interface_name)
            else:
                self.logger.info("Restored DHCP on interface %s" % interface_name)

        # Restore DHCP adapter settings
        for interface_name in self.adapters_dns_restore:

            cmd_del_dns = "netsh interface ip delete dns name=\"%s\" all" % interface_name
            cmd_set_dns_dhcp = "netsh interface ip set dns \"%s\" dhcp" % interface_name

            # Restore DNS on interface
            try:
                subprocess.check_call(cmd_del_dns, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.check_call(cmd_set_dns_dhcp, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError, e:
                self.logger.error("Failed to restore DNS on interface %s." % interface_name)
            else:
                self.logger.info("Restored DNS on interface %s" % interface_name)

        # Restore DNS server
        if self.is_set('modifylocaldns'):
            self.restore_dns_server()

        # Restart DNS service
        if self.is_set('stopdnsservice'):
            self.start_service_helper('Dnscache')  

        self.flush_dns()

    def old_stop(self):
        self.logger.info('Stopping...')
        if self.pcap:
            self.pcap.close()

        self.handle.close()

        # Restore DHCP adapter settings
        for interface_name in self.adapters_dhcp_restore:

            cmd_set_dhcp = "netsh interface ip set address name=\"%s\" dhcp" % interface_name

            # Restore DHCP on interface
            try:
                subprocess.check_call(cmd_set_dhcp, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError, e:
                self.logger.error("Failed to restore DHCP on interface %s." % interface_name)
            else:
                self.logger.info("Restored DHCP on interface %s" % interface_name)

        # Restore DHCP adapter settings
        for interface_name in self.adapters_dns_restore:

            cmd_del_dns = "netsh interface ip delete dns name=\"%s\" all" % interface_name
            cmd_set_dns_dhcp = "netsh interface ip set dns \"%s\" dhcp" % interface_name

            # Restore DNS on interface
            try:
                subprocess.check_call(cmd_del_dns, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.check_call(cmd_set_dns_dhcp, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError, e:
                self.logger.error("Failed to restore DNS on interface %s." % interface_name)
            else:
                self.logger.info("Restored DNS on interface %s" % interface_name)

        # Restore DNS server
        if self.is_set('modifylocaldns'):
            self.restore_dns_server()

        # Restart DNS service
        if self.is_set('stopdnsservice'):
            self.start_service_helper('Dnscache')  

        self.flush_dns()
        
    def handle_icmp_packet2(self, pkt):
        # Modify outgoing ICMP packet to target local Windows host which will reply to the ICMP messages.
        # HACK: Can't intercept inbound ICMP server, but still works for now.

        if not ((pkt.is_loopback and pkt.src_ip == self.loopback_ip and pkt.dst_ip == self.loopback_ip) or \
           (pkt.src_ip == self.external_ip and pkt.dst_ip == self.external_ip)):

            self.logger.info('Modifying %s ICMP packet:', 'loopback' if pkt.is_loopback else 'external')
            self.logger.info('  from: %s -> %s', pkt.src_ip, pkt.dst_ip)

            # Direct packet to the right interface IP address to avoid routing issues
            pkt.dst_ip = self.loopback_ip if pkt.is_loopback else self.external_ip

            self.logger.info('  to:   %s -> %s', pkt.src_ip, pkt.dst_ip)

        return pkt

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

    def check_black_white_list(self, packet, protocol, default_listener_port, blacklist_ports, conn_pid, process_name):
        """Return True if the packet matches a blacklist or does not match a
        whitelist
        """

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

        # Check host blacklist
        if packet.dst_addr in self.blacklist_hosts:
            self.logger.debug('Ignoring %s %s %s request packet to %s in the host blacklist.', direction_string, interface_string, protocol, packet.dst_addr)
            self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)   
            return True

        # Check the port host whitelist
        if packet.dst_addr and port_host_whitelist and \
            ((packet.dst_port in port_host_whitelist and not packet.dst_addr in port_host_whitelist[packet.dst_port]) or\
              (default_listener_port and default_listener_port in port_host_whitelist and not packet.dst_addr in port_host_whitelist[default_listener_port]))  :
            self.logger.debug('Ignoring %s %s %s request packet to %s not in the listener host whitelist.', direction_string, interface_string, protocol, packet.dst_addr)
            self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
            return True

        # Check the port host blacklist
        if packet.dst_addr and port_host_blacklist and \
            ((packet.dst_port in port_host_blacklist and packet.dst_addr in port_host_blacklist[packet.dst_port]) or\
              (default_listener_port and default_listener_port in port_host_blacklist and packet.dst_addr in port_host_blacklist[default_listener_port]))  :
            self.logger.debug('Ignoring %s %s %s request packet to %s in the listener host blacklist.', direction_string, interface_string, protocol, packet.dst_addr)
            self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
            return True

        if process_name:
            # Check process blacklist
            if process_name in self.blacklist_processes:
                self.logger.debug('Ignoring %s %s %s request packet from process %s in the process blacklist.', direction_string, interface_string, protocol, process_name)
                self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)                
                return True

            # Check the port process whitelist
            if port_process_whitelist and \
                ((packet.dst_port in port_process_whitelist and not process_name in port_process_whitelist[packet.dst_port]) or\
                  (default_listener_port and default_listener_port in port_process_whitelist and not process_name in port_process_whitelist[default_listener_port]))  :
                self.logger.debug('Ignoring %s %s %s request packet from process %s not in the listener process whitelist.', direction_string, interface_string, protocol, process_name)
                self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
                return True

            # Check the port process blacklist
            if port_process_blacklist and \
                ((packet.dst_port in port_process_blacklist and process_name in port_process_blacklist[packet.dst_port]) or\
                  (default_listener_port and default_listener_port in port_process_blacklist and process_name in port_process_blacklist[default_listener_port]))  :
                self.logger.debug('Ignoring %s %s %s request packet from process %s in the listener process blacklist.', direction_string, interface_string, protocol, process_name)
                self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
                return True

        return False

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

        bIsLoopback = (packet.is_loopback and
                       packet.src_addr == self.loopback_ip and
                       packet.dst_addr == self.loopback_ip)

        bIsBlacklistedPort = (packet.src_port in blacklist_ports or
                              packet.dst_port in blacklist_ports)

        # Pass as-is if the packet is a loopback packet
        if bIsLoopback:
            self.logger.debug('Ignoring loopback packet')
            self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
            return packet

        # Pass as-is if the source or destination port is in the blacklist
        if bIsBlacklistedPort:
            self.logger.debug('Forwarding blacklisted port %s %s %s packet:', direction_string, interface_string, protocol)
            self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
            return packet

        # Criteria to divert a packet to a local listener:
        # 1) Divert outbound packets only
        # 2) Make sure we are not diverting response packet based on the source port
        # 3) Make sure the destination port is a known diverted port or we have a default listener port defined
        bDivertLocally = (diverted_ports and
                          not packet.src_port in diverted_ports and
                          (packet.dst_port in diverted_ports or
                           default_listener_port != None))


        # Check to see if it is a listener reply needing fixups
        bIsListenerReply = diverted_ports and packet.src_port in diverted_ports

        ############################################################
        # If a packet must be diverted to a local listener
        ############################################################
        if bDivertLocally:
            # Find which process ID is sending the request
            conn_pid = self.get_pid_port_tcp(packet.src_port) if packet.tcp else self.get_pid_port_udp(packet.src_port)
            process_name = self.get_process_image_filename(conn_pid) if conn_pid else None

            # If the packet is in a blacklist, or is not in a whitelist, pass it as-is
            if self.check_black_white_list(packet, protocol, default_listener_port, blacklist_ports, conn_pid, process_name):
                return packet

            # Make sure you are not intercepting packets from one of the FakeNet listeners
            if conn_pid and os.getpid() == conn_pid:

                # HACK: FTP Passive Mode Handling
                # Check if a listener is initiating a new connection from a non-diverted port and add it to blacklist. This is done to handle a special use-case
                # of FTP ACTIVE mode where FTP server is initiating a new connection for which the response may be redirected to a default listener.
                # NOTE: Additional testing can be performed to check if this is actually a SYN packet
                if packet.dst_addr == self.external_ip and packet.src_addr == self.external_ip and not packet.src_port in diverted_ports and not packet.dst_port in diverted_ports:

                    self.logger.debug('Listener initiated connection %s %s %s:', direction_string, interface_string, protocol)
                    self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
                    self.logger.debug('  Blacklisted port %d', packet.src_port)

                    blacklist_ports.append(packet.src_port)

                else:
                    self.logger.debug('Skipping %s %s %s listener packet:', direction_string, interface_string, protocol)
                    self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

                return packet

            # Modify the packet

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
            # check if 'hidden' config is set. If so, the packet is 
            # directed to the default listener which is the proxy
            packet.dst_port = (packet.dst_port if (
                    packet.dst_port in diverted_ports and 
                    diverted_ports[packet.dst_port] is False) 
                    else default_listener_port)

            logger_level('  to:   %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

            if conn_pid:
                logger_level('  pid:  %d name: %s', conn_pid, process_name if process_name else 'Unknown')
            return packet


        ############################################################
        # Restore diverted response from a local listener
        # NOTE: The response can come from a legitimate request
        ############################################################
        if bIsListenerReply:
            # The packet is a response from a listener. It needs to be 
            # redirected to the original source

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

            return packet

        ############################################################
        # Catch-all / else case
        # At this point whe know the packet is either a response packet 
        # from a listener(sport is bound) or is bound for a port with no 
        # listener (dport not bound)
        ############################################################

        # Cache original target IP address based on source port
        self.sessions[packet.src_port] = (packet.dst_addr, packet.dst_port)
      
        # forward to proxy
        packet.dst_port = default_listener_port

        self.logger.debug('Redirected %s %s %s packet to proxy:', direction_string, interface_string, protocol)
        self.logger.debug('  %s:%d -> %s:%d', packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)

        return packet

    def handle_packet2(self, windivertpkt, pkt):
        # Preserve destination address to detect packet being diverted
        dst_addr = windivertpkt.dst_addr

        #######################################################################
        # Capture packet and store raw packet in the PCAP
        self.write_pcap(pkt.octets)

        ###########################################################################
        # Verify the IP packet has an additional header

        if pkt.ipver:

            #######################################################################
            # Handle ICMP Packets
  
            if pkt.is_icmp:
                pkt = self.handle_icmp_packet2(pkt)
                windivertpkt = pkt.windivertpkt

            #######################################################################
            # Handle TCP/UDP Packets

            elif pkt.proto_name: # If it is a recognized protocol...
                proto = pkt.proto_name
                windivertpkt = self.handle_tcp_udp_packet(windivertpkt, 
                                                    proto, 
                                                    self.default_listener[proto], 
                                                    self.blacklist_ports[proto])
            else:
                self.logger.error('ERROR: Unknown packet header type.')

        #######################################################################
        # Capture modified packet and store raw packet in the PCAP
        # NOTE: While this results in potentially duplicate traffic capture, this is necessary 
        #       to properly restore TLS/SSL sessions.
        # TODO: Develop logic to record traffic before modification for both requests and
        #       responses to reduce duplicate captures.
        if (dst_addr != windivertpkt.dst_addr):
            self.write_pcap(windivertpkt.raw.tobytes())

        #######################################################################
        # Attempt to send the processed packet
        try:
            self.handle.send(windivertpkt)
        except Exception, e:

            protocol = 'Unknown'

            if pkt.proto_name:
                protocol = pkt.proto_name
            elif pkt.is_icmp:
                protocol = 'ICMP'

            interface_string = 'loopback' if pkt.is_loopback else 'external'
            direction_string = 'inbound' if pkt.is_inbound else 'outbound'

            self.logger.error('ERROR: Failed to send %s %s %s packet', direction_string, interface_string, protocol)

            if windivertpkt.src_port and windivertpkt.dst_port:
                self.logger.error('  %s:%d -> %s:%d', windivertpkt.src_addr, windivertpkt.src_port, windivertpkt.dst_addr, windivertpkt.dst_port)
            else:
                self.logger.error('  %s -> %s', windivertpkt.src_addr, windivertpkt.dst_addr)

            self.logger.error('  %s', e)

    def handle_packet(self, packet):

        if packet == None:
            self.logger.error('ERROR: Can\'t handle packet.')
            return

        # Preserve destination address to detect packet being diverted
        dst_addr = packet.dst_addr

        #######################################################################
        # Capture packet and store raw packet in the PCAP
        self.write_pcap(packet.raw.tobytes())

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
                                                    self.default_listener[protocol], 
                                                    self.blacklist_ports[protocol])

            elif packet.udp:
                protocol = 'UDP'
                packet = self.handle_tcp_udp_packet(packet,
                                                    protocol,
                                                    self.default_listener[protocol], 
                                                    self.blacklist_ports[protocol])

            else:
                self.logger.error('ERROR: Unknown packet header type.')

        #######################################################################
        # Capture modified packet and store raw packet in the PCAP
        # NOTE: While this results in potentially duplicate traffic capture, this is necessary 
        #       to properly restore TLS/SSL sessions.
        # TODO: Develop logic to record traffic before modification for both requests and
        #       responses to reduce duplicate captures.
        if (dst_addr != packet.dst_addr):
            self.write_pcap(packet.raw.tobytes())

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
