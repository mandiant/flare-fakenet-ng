# Diverter for Windows implemented using WinDivert library

import logging

from pydivert.windivert import *

import socket

import os
import dpkt
from . import fnpacket

import time
import threading
import platform

from winutil import *
from diverterbase import *

import subprocess


class WindowsPacketCtx(fnpacket.PacketCtx):
    def __init__(self, lbl, wdpkt):
        self.wdpkt = wdpkt
        raw = wdpkt.raw.tobytes()

        super(WindowsPacketCtx, self).__init__(lbl, raw)

    # Packet mangling properties are extended here to also write the data to
    # the pydivert.Packet object. This is because there appears to be no way to
    # populate the pydivert.Packet object with plain octets unless you can also
    # provide @interface and @direction arguments which do not appear at a
    # glance to be directly available as attributes of pydivert.Packet,
    # according to https://ffalcinelli.github.io/pydivert/
    #
    # Perhaps we can get these from wd_addr?

    # src_ip overrides

    @property
    def src_ip(self):
        return self._src_ip

    @src_ip.setter
    def src_ip(self, new_srcip):
        super(self.__class__, self.__class__).src_ip.fset(self, new_srcip)
        self.wdpkt.src_addr = new_srcip

    # dst_ip overrides

    @property
    def dst_ip(self):
        return self._dst_ip

    @dst_ip.setter
    def dst_ip(self, new_dstip):
        super(self.__class__, self.__class__).dst_ip.fset(self, new_dstip)
        self.wdpkt.dst_addr = new_dstip

    # sport overrides

    @property
    def sport(self):
        return self._sport

    @sport.setter
    def sport(self, new_sport):
        super(self.__class__, self.__class__).sport.fset(self, new_sport)
        if self.proto:
            self.wdpkt.src_port = new_sport

    # dport overrides

    @property
    def dport(self):
        return self._dport

    @dport.setter
    def dport(self, new_dport):
        super(self.__class__, self.__class__).dport.fset(self, new_dport)
        if self.proto:
            self.wdpkt.dst_port = new_dport


class Diverter(DiverterBase, WinUtilMixin):

    def __init__(self, diverter_config, listeners_config, ip_addrs,
                 logging_level=logging.INFO):

        # Populated by winutil and used to restore modified Interfaces back to
        # DHCP
        self.adapters_dhcp_restore = list()
        self.adapters_dns_restore = list()

        super(Diverter, self).__init__(diverter_config, listeners_config,
                                       ip_addrs, logging_level)

        self.running_on_windows = True

        if not self.single_host_mode:
            self.logger.critical('Windows diverter currently only supports '
                                 'SingleHost mode')
            sys.exit(1)

        # Used (by winutil) for caching of DNS server names prior to changing
        self.adapters_dns_server_backup = dict()

        # Configure external and loopback IP addresses
        self.external_ip = self.get_best_ipaddress()
        if not self.external_ip:
            self.external_ip = self.get_ip_with_gateway()
        if not self.external_ip:
            self.external_ip = socket.gethostbyname(socket.gethostname())

        self.logger.debug('External IP: %s Loopback IP: %s' %
                          (self.external_ip, self.loopback_ip))

        #######################################################################
        # Initialize filter and WinDivert driver

        # Interpose on all IP datagrams so they appear in the pcap, let
        # DiverterBase decide whether they're actually forwarded etc.
        self.filter = 'outbound and ip'

        # Initialize WinDivert
        try:
            self.handle = WinDivert(filter=self.filter)
            self.handle.open()
        except WindowsError, e:
            if e.winerror == 5:
                self.logger.critical('ERROR: Insufficient privileges to run '
                                     'windows diverter.')
                self.logger.critical('       Please restart with '
                                     'Administrator privileges.')
                sys.exit(1)
            elif e.winerror == 3:
                self.logger.critical('ERROR: Could not locate WinDivert DLL '
                                     'or one of its components.')
                self.logger.critical('       Please make sure you have copied '
                                     'FakeNet-NG to the C: drive.')
                sys.exit(1)
            else:
                self.logger.critical('ERROR: Failed to open a handle to the '
                                     'WinDivert driver: %s', e)
                sys.exit(1)

    ###########################################################################
    # Diverter controller functions

    def startCallback(self):
        # Set local DNS server IP address
        if self.is_set('modifylocaldns'):
            self.set_dns_server(self.external_ip)

        # Stop DNS service
        if self.is_set('stopdnsservice'):
            self.stop_service_helper('Dnscache')

        self.logger.debug('Diverting ports: ')

        self.flush_dns()

        self.diverter_thread = threading.Thread(target=self.divert_thread)
        self.diverter_thread.daemon = True

        self.diverter_thread.start()

        return True

    def divert_thread(self):
        try:
            while True:
                wdpkt = self.handle.recv()

                if wdpkt is None:
                    self.logger.error('ERROR: Can\'t handle packet.')
                    continue

                pkt = WindowsPacketCtx('divert_thread', wdpkt)

                cb3 = [
                    self.check_log_icmp,
                    self.redirIcmpIpUnconditionally
                    ]
                cb4 = [
                    self.maybe_redir_port,
                    self.maybe_fixup_sport,
                    self.maybe_redir_ip,
                    self.maybe_fixup_srcip,
                    ]

                self.handle_pkt(pkt, cb3, cb4)

                # Attempt to send the processed packet
                self.setLastErrorNull()  # WinDivert/LastError workaround
                try:
                    self.handle.send(pkt.wdpkt)
                except Exception, e:

                    protocol = 'Unknown'

                    if pkt.proto:
                        protocol = pkt.proto
                    elif pkt.is_icmp:
                        protocol = 'ICMP'

                    self.logger.error('ERROR: Failed to send %s %s %s packet',
                                      self.pktDirectionStr(pkt),
                                      self.pktInterfaceStr(pkt), protocol)
                    self.logger.error('  %s' % (pkt.hdrToStr()))
                    self.logger.error('  %s', e)

        except WindowsError as e:
            if e.winerror in [4, 6, 995]:
                return
            else:
                raise

    def stopCallback(self):
        if self.pcap:
            self.pcap.close()

        self.handle.close()

        # Restore DHCP adapter settings
        for interface_name in self.adapters_dhcp_restore:

            cmd_set_dhcp = ('netsh interface ip set address name="%s" dhcp' %
                            interface_name)

            # Restore DHCP on interface
            try:
                subprocess.check_call(cmd_set_dhcp, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError, e:
                self.logger.error('Failed to restore DHCP on interface %s.' %
                                  interface_name)
            else:
                self.logger.info('Restored DHCP on interface %s' %
                                 interface_name)

        # Restore DHCP adapter settings
        for interface_name in self.adapters_dns_restore:

            cmd_del_dns = ('netsh interface ip delete dns name="%s" all' %
                           interface_name)
            cmd_set_dns_dhcp = ('netsh interface ip set dns "%s" dhcp' %
                                interface_name)

            # Restore DNS on interface
            try:
                subprocess.check_call(cmd_del_dns, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
                subprocess.check_call(cmd_set_dns_dhcp, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError, e:
                self.logger.error("Failed to restore DNS on interface %s." %
                                  interface_name)
            else:
                self.logger.info("Restored DNS on interface %s" %
                                 interface_name)

        # Restore DNS server
        if self.is_set('modifylocaldns'):
            self.restore_dns_server()

        # Restart DNS service
        if self.is_set('stopdnsservice'):
            self.start_service_helper('Dnscache')

        self.flush_dns()

        return True

    def pktInterfaceStr(self, pkt):
        """WinDivert provides is_loopback which Windows Diverter uses to
        display information about the disposition of packets it is
        processing during error and other cases.
        """
        return 'loopback' if pkt.wdpkt.is_loopback else 'external'

    def pktDirectionStr(self, pkt):
        """WinDivert provides is_inbound which Windows Diverter uses to
        display information about the disposition of packets it is
        processing during error and other cases.
        """
        return 'inbound' if pkt.wdpkt.is_inbound else 'outbound'

    def redirIcmpIpUnconditionally(self, crit, pkt):
        """Redirect ICMP to loopback or external IP if necessary.

        On Windows, we can't conveniently use an iptables REDIRECT rule to get
        ICMP packets sent back home for free, so here is some code.
        """
        if (pkt.is_icmp and
                pkt.dst_ip not in [self.loopback_ip, self.external_ip]):
            self.logger.info('Modifying ICMP packet (type %d, code %d):' %
                             (pkt.icmp_type, pkt.icmp_code))
            self.logger.info('  from: %s' % (pkt.hdrToStr()))
            pkt.dst_ip = self.getNewDestinationIp(pkt.src_ip)
            self.logger.info('  to:   %s' % (pkt.hdrToStr()))

        return pkt


def main():

    diverter_config = {'redirectalltraffic': 'no',
                       'defaultlistener': 'DefaultListener',
                       'dumppackets': 'no'}
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
