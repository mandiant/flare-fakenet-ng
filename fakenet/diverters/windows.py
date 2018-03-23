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
    def __init__(self, lbl, wdpkt, local_ips):
        self.wdpkt = wdpkt
        raw = wdpkt.raw.tobytes()

        super(WindowsPacketCtx, self).__init__(lbl, raw)

        self.is_loopback0 = wdpkt.is_loopback
        self.is_inbound0 = wdpkt.is_inbound
        self.interface_string = 'loopback' if self.is_loopback0 else 'external'
        self.direction_string = 'inbound' if self.is_inbound0 else 'outbound'

    # Packet mangling properties are extended here to also write the data to
    # the pydivert.Packet object. This is because there appears to be no way to
    # populate the pydivert.Packet object with plain octets unless you can also
    # provide @interface and @direction arguments which do not appear at a
    # glance to be available as attributes of pydivert.Packet, according to
    # https://ffalcinelli.github.io/pydivert/

    # src_ip overrides

    @property
    def src_ip(self): return self._src_ip

    @src_ip.setter
    def src_ip(self, new_srcip):
        super(self.__class__, self.__class__).src_ip.fset(self, new_srcip)
        self.wdpkt.src_addr = new_srcip

    # dst_ip overrides

    @property
    def dst_ip(self): return self._dst_ip

    @dst_ip.setter
    def dst_ip(self, new_dstip):
        super(self.__class__, self.__class__).dst_ip.fset(self, new_dstip)
        self.wdpkt.dst_addr = new_dstip

    # sport overrides

    @property
    def sport(self): return self._sport

    @sport.setter
    def sport(self, new_sport):
        super(self.__class__, self.__class__).sport.fset(self, new_sport)
        if self.proto_name:
            self.wdpkt.src_port = new_sport

    # dport overrides

    @property
    def dport(self): return self._dport

    @dport.setter
    def dport(self, new_dport):
        super(self.__class__, self.__class__).dport.fset(self, new_dport)
        if self.proto_name:
            self.wdpkt.dst_port = new_dport


class Diverter(DiverterBase, WinUtilMixin):

    def __init__(self, diverter_config, listeners_config, ip_addrs, logging_level = logging.INFO):

        self.init_base(diverter_config, listeners_config, ip_addrs, logging_level)

        if not self.single_host_mode:
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
    # Diverter controller functions

    def start(self):
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

    def get_pid_comm(self, pkt):
        conn_pid = self.get_pid_port_tcp(pkt.sport) if (pkt.proto_name == 'TCP') else self.get_pid_port_udp(pkt.sport)
        process_name = self.get_process_image_filename(conn_pid) if conn_pid else None
        return conn_pid, process_name

    def divert_thread(self):
        try:
            while True:
                wdpkt = self.handle.recv()

                if wdpkt == None:
                    self.logger.error('ERROR: Can\'t handle packet.')
                    continue

                pkt = WindowsPacketCtx('divert_thread', wdpkt, self.ip_addrs)

                cb3 = [self.handle_icmp_packet,]
                cb4 = [self.handle_tcp_udp_packet,]
                self.handle_pkt(pkt, cb3, cb4)

                #######################################################################
                # Attempt to send the processed packet
                try:
                    self.handle.send(pkt.wdpkt)
                except Exception, e:

                    protocol = 'Unknown'

                    if pkt.proto_name:
                        protocol = pkt.proto_name
                    elif pkt.is_icmp:
                        protocol = 'ICMP'

                    self.logger.error('ERROR: Failed to send %s %s %s packet', pkt.direction_string, pkt.interface_string, protocol)
                    self.logger.error('  %s' % (pkt.hdrToStr()))
                    self.logger.error('  %s', e)

        except WindowsError as e:
            if e.winerror in [4, 6, 995]:
                return
            else:
                raise

    def stop(self):
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

    def handle_icmp_packet(self, pkt):
        if pkt.is_icmp:
            # Modify outgoing ICMP packet to target local Windows host which will reply to the ICMP messages.
            # HACK: Can't intercept inbound ICMP server, but still works for now.

            if not ((pkt.is_loopback0 and pkt.src_ip == self.loopback_ip and pkt.dst_ip == self.loopback_ip) or \
               (pkt.src_ip == self.external_ip and pkt.dst_ip == self.external_ip)):

                self.logger.info('Modifying %s ICMP packet:', 'loopback' if pkt.is_loopback0 else 'external')
                self.logger.info('  from: %s -> %s', pkt.src_ip, pkt.dst_ip)

                # Direct packet to the right interface IP address to avoid routing issues
                pkt.dst_ip = self.loopback_ip if pkt.is_loopback0 else self.external_ip

                self.logger.info('  to:   %s -> %s', pkt.src_ip, pkt.dst_ip)

        return pkt

    def handle_tcp_udp_packet(self, pkt, pid, process_name):

        # Protocol specific filters
        protocol = pkt.proto_name
        default_listener_port  = self.default_listener.get(protocol)
        blacklist_ports        = self.blacklist_ports.get(protocol)
        diverted_ports         = self.diverted_ports.get(protocol)
        port_process_whitelist = self.port_process_whitelist.get(protocol)
        port_process_blacklist = self.port_process_blacklist.get(protocol)
        port_host_whitelist    = self.port_host_whitelist.get(protocol)
        port_host_blacklist    = self.port_host_blacklist.get(protocol)
        port_execute           = self.port_execute.get(protocol)

        bIsLoopback = (pkt.is_loopback0 and
                       pkt.src_ip == self.loopback_ip and
                       pkt.dst_ip == self.loopback_ip)

        # Pass as-is if the packet is a loopback packet
        if bIsLoopback:
            self.logger.debug('Ignoring loopback packet')
            self.logger.debug('  %s:%d -> %s:%d', pkt.src_ip, pkt.sport, pkt.dst_ip, pkt.dport)
            return pkt

        # Criteria to divert a packet to a local listener:
        # 1) Divert outbound packets only
        # 2) Make sure we are not diverting response packet based on the source port
        # 3) Make sure the destination port is a known diverted port or we have a default listener port defined
        bDivertLocally = (diverted_ports and
                          not pkt.sport in diverted_ports and
                          (pkt.dport in diverted_ports or
                           default_listener_port != None))


        # Check to see if it is a listener reply needing fixups
        bIsListenerReply = diverted_ports and pkt.sport in diverted_ports

        ############################################################
        # If a packet must be diverted to a local listener
        ############################################################
        if bDivertLocally:
            # If the packet is in a blacklist, or is not in a whitelist, pass it as-is
            if self.check_should_ignore(pkt, pid, process_name):
                return pkt

            # Modify the packet

            # Adjustable log level output. Used to display info level logs for first packets of the session and 
            # debug level for the rest of the communication in order to reduce log output.
            logger_level = self.logger.debug

            # First packet in a new session
            if not (pkt.sport in self.sessions and self.sessions[pkt.sport] == (pkt.dst_ip, pkt.dport)):

                # Cache original target IP address based on source port
                self.sessions[pkt.sport] = (pkt.dst_ip, pkt.dport)

                # Override log level to display all information on info level
                logger_level = self.logger.info

                # Execute command
                if pid and port_execute and (pkt.dport in port_execute or (default_listener_port and default_listener_port in port_execute)):


                    execute_cmd = port_execute[pkt.dport if pkt.dport in diverted_ports else default_listener_port].format(pid = pid, 
                                                                           procname = process_name, 
                                                                           src_addr = pkt.src_ip, 
                                                                           src_port = pkt.sport,
                                                                           dst_addr = pkt.dst_ip,
                                                                           dst_port = pkt.dport)

                    logger_level('Executing command: %s', execute_cmd)

                    self.execute_detached(execute_cmd)       


            logger_level('Modifying %s %s %s request packet:', pkt.direction_string, pkt.interface_string, protocol)
            logger_level('  from: %s:%d -> %s:%d', pkt.src_ip, pkt.sport, pkt.dst_ip, pkt.dport)

            # Direct packet to the right interface IP address to avoid routing issues
            pkt.dst_ip = self.loopback_ip if pkt.is_loopback0 else self.external_ip

            # Direct packet to an existing or a default listener
            # check if 'hidden' config is set. If so, the packet is 
            # directed to the default listener which is the proxy
            pkt.dport = (pkt.dport if (
                    pkt.dport in diverted_ports and 
                    diverted_ports[pkt.dport] is False) 
                    else default_listener_port)

            logger_level('  to:   %s:%d -> %s:%d', pkt.src_ip, pkt.sport, pkt.dst_ip, pkt.dport)

            if pid:
                logger_level('  pid:  %d name: %s', pid, process_name if process_name else 'Unknown')
            return pkt


        ############################################################
        # Restore diverted response from a local listener
        # NOTE: The response can come from a legitimate request
        ############################################################
        if bIsListenerReply:
            # The packet is a response from a listener. It needs to be 
            # redirected to the original source

            # Find which process ID is sending the request
            pid = self.get_pid_port_tcp(pkt.dport) if (pkt.proto_name == 'TCP') else self.get_pid_port_udp(pkt.dport)
            process_name = self.get_process_image_filename(pid)

            if not pkt.dport in self.sessions:
                self.logger.debug('Unknown %s %s %s response packet:', pkt.direction_string, pkt.interface_string, protocol)
                self.logger.debug('  %s:%d -> %s:%d', pkt.src_ip, pkt.sport, pkt.dst_ip, pkt.dport)

            # Restore original target IP address from the cache
            else:
                self.logger.debug('Modifying %s %s %s response packet:', pkt.direction_string, pkt.interface_string, protocol)
                self.logger.debug('  from: %s:%d -> %s:%d', pkt.src_ip, pkt.sport, pkt.dst_ip, pkt.dport)

                # Restore original target IP address based on destination port
                pkt.src_ip, pkt.sport = self.sessions[pkt.dport]

                self.logger.debug('  to:   %s:%d -> %s:%d', pkt.src_ip, pkt.sport, pkt.dst_ip, pkt.dport)

            if pid:
                self.logger.debug('  pid:  %d name: %s', pid, process_name if process_name else 'Unknown')

            return pkt

        ############################################################
        # Catch-all / else case
        # At this point whe know the packet is either a response packet 
        # from a listener(sport is bound) or is bound for a port with no 
        # listener (dport not bound)
        ############################################################

        # Cache original target IP address based on source port
        self.sessions[pkt.sport] = (pkt.dst_ip, pkt.dport)
      
        # forward to proxy
        pkt.dport = default_listener_port

        self.logger.debug('Redirected %s %s %s packet to proxy:', pkt.direction_string, pkt.interface_string, protocol)
        self.logger.debug('  %s:%d -> %s:%d', pkt.src_ip, pkt.sport, pkt.dst_ip, pkt.dport)

        return pkt

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
