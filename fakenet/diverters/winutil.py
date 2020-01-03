#!/usr/bin/env python
import logging
logging.basicConfig(format='%(asctime)s [%(name)18s] %(message)s',
                    datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)

import ctypes
from ctypes import *
from ctypes.wintypes import *

import os
import sys
import socket
import struct
from . import diverterbase

import time

from _winreg import *

import subprocess

NO_ERROR = 0

AF_INET = 2
AF_INET6 = 23

ULONG64 = c_uint64


##############################################################################
# Services related functions
##############################################################################

SC_MANAGER_ALL_ACCESS = 0xF003F

SERVICE_ALL_ACCESS = 0xF01FF
SERVICE_STOP = 0x0020
SERVICE_QUERY_STATUS = 0x0004
SERVICE_ENUMERATE_DEPENDENTS = 0x0008

SC_STATUS_PROCESS_INFO = 0x0

SERVICE_STOPPED = 0x1
SERVICE_START_PENDING = 0x2
SERVICE_STOP_PENDING = 0x3
SERVICE_RUNNING = 0x4
SERVICE_CONTINUE_PENDING = 0x5
SERVICE_PAUSE_PENDING = 0x6
SERVICE_PAUSED = 0x7

SERVICE_CONTROL_STOP = 0x1
SERVICE_CONTROL_PAUSE = 0x2
SERVICE_CONTROL_CONTINUE = 0x3

SERVICE_NO_CHANGE = 0xffffffff

SERVICE_AUTO_START = 0x2
SERVICE_BOOT_START = 0x0
SERVICE_DEMAND_START = 0x3
SERVICE_DISABLED = 0x4
SERVICE_SYSTEM_START = 0x1


class SERVICE_STATUS_PROCESS(Structure):
    _fields_ = [
        ("dwServiceType",             DWORD),
        ("dwCurrentState",            DWORD),
        ("dwControlsAccepted",        DWORD),
        ("dwWin32ExitCode",           DWORD),
        ("dwServiceSpecificExitCode", DWORD),
        ("dwCheckPoint",              DWORD),
        ("dwWaitHint",                DWORD),
        ("dwProcessId",               DWORD),
        ("dwServiceFlags",            DWORD),
    ]

##############################################################################
# Process related functions
##############################################################################

##############################################################################
# GetExtendedTcpTable constants and structures


TCP_TABLE_OWNER_PID_ALL = 5


class MIB_TCPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwState",      DWORD),
        ("dwLocalAddr",  DWORD),
        ("dwLocalPort",  DWORD),
        ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD),
        ("dwOwningPid",  DWORD)
    ]


class MIB_TCPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table",        MIB_TCPROW_OWNER_PID * 512)
    ]

##############################################################################
# GetExtendedUdpTable constants and structures


UDP_TABLE_OWNER_PID = 1


class MIB_UDPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD)
    ]


class MIB_UDPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table",        MIB_UDPROW_OWNER_PID * 512)
    ]

###############################################################################
# GetProcessImageFileName constants and structures


MAX_PATH = 260
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


###############################################################################
# Network interface related functions
###############################################################################

MIB_IF_TYPE_ETHERNET = 6
MIB_IF_TYPE_LOOPBACK = 28
IF_TYPE_IEEE80211 = 71

###############################################################################
# GetAdaptersAddresses constants and structures

MAX_ADAPTER_ADDRESS_LENGTH = 8
MAX_DHCPV6_DUID_LENGTH = 130

IFOPERSTATUSUP = 1


class SOCKADDR(Structure):
    _fields_ = [
        ("sa_family",           c_ushort),
        ("sa_data",             c_char * 14),
    ]


class SOCKET_ADDRESS(Structure):
    _fields_ = [
        ("Sockaddr",            POINTER(SOCKADDR)),
        ("SockaddrLength",      INT),
    ]


class IP_ADAPTER_PREFIX(Structure):
    pass


IP_ADAPTER_PREFIX._fields_ = [
    ("Length",              ULONG),
    ("Flags",               DWORD),
    ("Next",                POINTER(IP_ADAPTER_PREFIX)),
    ("Address",             SOCKET_ADDRESS),
    ("PrefixLength",        ULONG),
]


class IP_ADAPTER_ADDRESSES(Structure):
    pass


IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length",                  ULONG),
    ("IfIndex",                 DWORD),
    ("Next",                    POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName",             LPSTR),
    ("FirstUnicastAddress",     c_void_p),  # Not used
    ("FirstAnycastAddress",     c_void_p),  # Not used
    ("FirstMulticastAddress",   c_void_p),  # Not used
    ("FirstDnsServerAddress",   c_void_p),  # Not used
    ("DnsSuffix",               LPWSTR),
    ("Description",             LPWSTR),
    ("FriendlyName",            LPWSTR),
    ("PhysicalAddress",         BYTE * MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength",   DWORD),
    ("Flags",                   DWORD),
    ("Mtu",                     DWORD),
    ("IfType",                  DWORD),
    ("OperStatus",              DWORD),
    ("Ipv6IfIndex",             DWORD),
    ("ZoneIndices",             DWORD * 16),
    ("FirstPrefix",             POINTER(IP_ADAPTER_PREFIX)),
    ("TransmitLinkSpeed",       ULONG64),
    ("ReceiveLinkSpeed",        ULONG64),
    ("FirstWinsServerAddress",  c_void_p),  # Not used
    ("FirstGatewayAddress",     c_void_p),  # Not used
    ("Ipv4Metric",              ULONG),
    ("Ipv6Metric",              ULONG),
    ("Luid",                    ULONG64),
    ("Dhcpv4Server",            SOCKET_ADDRESS),
    ("CompartmentId",           DWORD),
    ("NetworkGuid",             BYTE * 16),
    ("ConnectionType",          DWORD),
    ("TunnelType",              DWORD),
    ("Dhcpv6Server",            SOCKET_ADDRESS),
    ("Dhcpv6ClientDuid",        BYTE * MAX_DHCPV6_DUID_LENGTH),
    ("Dhcpv6ClientDuidLength",  ULONG),
    ("Dhcpv6Iaid",              ULONG),
    ("FirstDnsSuffix",          c_void_p),  # Not used
]

###############################################################################
# GetAdaptersInfo constants and structures

MAX_ADAPTER_NAME_LENGTH = 256
MAX_ADAPTER_DESCRIPTION_LENGTH = 128
MAX_ADAPTER_LENGTH = 8

MIB_IF_TYPE_ETHERNET = 6
MIB_IF_TYPE_LOOPBACK = 28
IF_TYPE_IEEE80211 = 71


class IP_ADDRESS_STRING(Structure):
    _fields_ = [
        ("String",               c_char * 16),
    ]


class IP_MASK_STRING(Structure):
    _fields_ = [
        ("String",               c_char * 16),
    ]


class IP_ADDR_STRING(Structure):
    pass


IP_ADDR_STRING._fields_ = [
    ("Next",                POINTER(IP_ADDR_STRING)),
    ("IpAddress",           IP_ADDRESS_STRING),
    ("IpMask",              IP_MASK_STRING),
    ("Context",             DWORD),
]


class IP_ADAPTER_INFO(Structure):
    pass


IP_ADAPTER_INFO._fields_ = [
    ("Next",                POINTER(IP_ADAPTER_INFO)),
    ("ComboIndex",          DWORD),
    ("AdapterName",         c_char * (MAX_ADAPTER_NAME_LENGTH + 4)),
    ("Description",         c_char * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
    ("AddressLength",       UINT),
    ("Address",             BYTE * MAX_ADAPTER_LENGTH),
    ("Index",               DWORD),
    ("Type",                UINT),
    ("DhcpEnabled",         UINT),
    ("CurrentIpAddress",    c_void_p),  # Not used
    ("IpAddressList",       IP_ADDR_STRING),
    ("GatewayList",         IP_ADDR_STRING),
    ("DhcpServer",          IP_ADDR_STRING),
    ("HaveWins",            BOOL),
    ("PrimaryWinsServer",   IP_ADDR_STRING),
    ("SecondaryWinsServer", IP_ADDR_STRING),
    ("LeaseObtained",       c_ulong),
    ("LeaseExpires",        c_ulong),

]

###############################################################################
# GetNetworkParams constants and structures

MAX_HOSTNAME_LEN = 128
MAX_DOMAIN_NAME_LEN = 128
MAX_SCOPE_ID_LEN = 256

###############################################################################
# ConvertInterface constants and structures

NDIS_IF_MAX_STRING_SIZE = 256


class IP_ADDRESS_STRING(Structure):
    _fields_ = [
        ("String",               c_char * 16),
    ]


class IP_MASK_STRING(Structure):
    _fields_ = [
        ("String",               c_char * 16),
    ]


class IP_ADDR_STRING(Structure):
    pass


IP_ADDR_STRING._fields_ = [
    ("Next",                POINTER(IP_ADDR_STRING)),
    ("IpAddress",           IP_ADDRESS_STRING),
    ("IpMask",              IP_MASK_STRING),
    ("Context",             DWORD),
]


class FIXED_INFO(Structure):
    _fields_ = [
        ("HostName",            c_char * (MAX_HOSTNAME_LEN + 4)),
        ("DomainName",          c_char * (MAX_DOMAIN_NAME_LEN + 4)),
        ("CurrentDnsServer",    c_void_p),  # Not used
        ("DnsServerList",       IP_ADDR_STRING),
        ("NodeType",            UINT),
        ("ScopeId",             c_char * (MAX_SCOPE_ID_LEN + 4)),
        ("EnableRouting",       UINT),
        ("EnableProxy",         UINT),
        ("EnableDns",           UINT),
    ]


class WinUtilMixin(diverterbase.DiverterPerOSDelegate):
    def getNewDestinationIp(self, src_ip):
        """Gets the IP to redirect to - loopback if loopback, external
        otherwise.

        On Windows, and possibly other operating systems, if you redirect
        external packets to a loopback address, they simply will not route.

        On Linux, FTP tests will fail if you do this, so it is overridden to
        return 127.0.0.1.
        """
        return self.loopback_ip if src_ip.startswith('127.') else self.external_ip

    def fix_gateway(self):
        """Check if there is a gateway configured on any of the Ethernet
        interfaces. If that's not the case, then locate configured IP address
        and set a gateway automatically. This is necessary for VMWare Host-Only
        DHCP server which leaves default gateway empty.
        """
        fixed = False

        for adapter in self.get_adapters_info():

            # Look for a DHCP interface with a set IP address but no gateway
            # (Host-Only)
            if self.check_ipaddresses_interface(adapter) and adapter.DhcpEnabled:

                (ip_address, netmask) = next(
                    self.get_ipaddresses_netmask(adapter))
                gw_address = ip_address[:ip_address.rfind('.')] + '.254'

                interface_name = self.get_adapter_friendlyname(adapter.Index)

                # Don't set gateway on loopback interfaces (e.g. Npcap Loopback
                # Adapter)
                if not "loopback" in interface_name.lower():

                    self.adapters_dhcp_restore.append(interface_name)

                    cmd_set_gw = "netsh interface ip set address name=\"%s\" static %s %s %s" % (
                        interface_name, ip_address, netmask, gw_address)

                    # Configure gateway
                    try:
                        subprocess.check_call(cmd_set_gw, shell=True,
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE)
                    except subprocess.CalledProcessError, e:
                        self.logger.error("         Failed to set gateway %s on interface %s."
                                          % (gw_address, interface_name))
                    else:
                        self.logger.info("         Setting gateway %s on interface %s"
                                % (gw_address, interface_name))
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

                # Don't set DNS on loopback interfaces (e.g. Npcap Loopback
                # Adapter)
                if not "loopback" in interface_name.lower():

                    self.adapters_dns_restore.append(interface_name)

                    cmd_set_dns = "netsh interface ip set dns name=\"%s\" static %s" % (
                        interface_name, dns_address)

                    # Configure DNS server
                    try:
                        subprocess.check_call(cmd_set_dns,
                                              shell=True,
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE)
                    except subprocess.CalledProcessError, e:
                        self.logger.error("         Failed to set DNS %s on interface %s."
                                          % (dns_address, interface_name))
                    else:
                        self.logger.info("         Setting DNS %s on interface %s"
                                         % (dns_address, interface_name))
                        fixed = True

        return fixed

    def get_pid_comm(self, pkt):
        conn_pid, process_name = None, None
        if pkt.proto and pkt.sport:
            if pkt.proto == 'TCP':
                conn_pid = self._get_pid_port_tcp(pkt.sport)
            elif pkt.proto == 'UDP':
                conn_pid = self._get_pid_port_udp(pkt.sport)

            if conn_pid:
                process_name = self.get_process_image_filename(conn_pid)
        return conn_pid, process_name

    def check_gateways(self):

        for adapter in self.get_adapters_info():
            for gateway in self.get_gateways(adapter):
                if gateway != '0.0.0.0':
                    return True
        else:
            return False

    def check_ipaddresses(self):

        for adapter in self.get_adapters_info():
            if self.check_ipaddresses_interface(adapter):
                return True
        else:
            return False

    def check_dns_servers(self):

        FixedInfo = self.get_network_params()

        if not FixedInfo:
            return

        ip_addr_string = FixedInfo.DnsServerList

        if ip_addr_string and ip_addr_string.IpAddress.String:
            return True

        else:
            return False

    ###########################################################################
    # Service related functions
    ###########################################################################

    ###########################################################################
    # Establishes a connection to the service control manager on the specified computer and opens the specified service control manager database.
    #
    # SC_HANDLE WINAPI OpenSCManager(
    #   _In_opt_ LPCTSTR lpMachineName,
    #   _In_opt_ LPCTSTR lpDatabaseName,
    #   _In_     DWORD   dwDesiredAccess
    # );

    def open_sc_manager(self):

        sc_handle = windll.advapi32.OpenSCManagerA(0, 0, SC_MANAGER_ALL_ACCESS)
        if sc_handle == 0:
            self.logger.error("Failed to call OpenSCManager")
            return

        return sc_handle

    ###########################################################################
    # Closes a handle to a service control manager or service object
    #
    # BOOL WINAPI CloseServiceHandle(
    # _In_ SC_HANDLE hSCObject
    # );

    def close_service_handle(self, sc_handle):

        if windll.advapi32.CloseServiceHandle(sc_handle) == 0:
            self.logger.error('Failed to call CloseServiceHandle')
            return False

        return True

    ###########################################################################
    # Opens an existing service.
    #
    # SC_HANDLE WINAPI OpenService(
    #   _In_ SC_HANDLE hSCManager,
    #   _In_ LPCTSTR   lpServiceName,
    #   _In_ DWORD     dwDesiredAccess
    # );

    def open_service(self, sc_handle, service_name,
                     dwDesiredAccess=SERVICE_ALL_ACCESS):

        if not sc_handle:
            return

        service_handle = windll.advapi32.OpenServiceA(sc_handle, service_name,
                                                      dwDesiredAccess)

        if service_handle == 0:
            self.logger.error('Failed to call OpenService')
            return

        return service_handle

    ###########################################################################
    # Retrieves the current status of the specified service based on the specified information level.
    #
    # BOOL WINAPI QueryServiceStatusEx(
    #   _In_      SC_HANDLE      hService,
    #   _In_      SC_STATUS_TYPE InfoLevel,
    #   _Out_opt_ LPBYTE         lpBuffer,
    #   _In_      DWORD          cbBufSize,
    #   _Out_     LPDWORD        pcbBytesNeeded
    # );

    def query_service_status_ex(self, service_handle):

        lpBuffer = SERVICE_STATUS_PROCESS()
        cbBufSize = DWORD(sizeof(SERVICE_STATUS_PROCESS))
        pcbBytesNeeded = DWORD()

        if windll.advapi32.QueryServiceStatusEx(service_handle, SC_STATUS_PROCESS_INFO, byref(lpBuffer), cbBufSize, byref(pcbBytesNeeded)) == 0:
            self.logger.error('Failed to call QueryServiceStatusEx')
            return

        return lpBuffer

    ###########################################################################
    # Sends a control code to a service.
    #
    # BOOL WINAPI ControlService(
    #   _In_  SC_HANDLE        hService,
    #   _In_  DWORD            dwControl,
    #   _Out_ LPSERVICE_STATUS lpServiceStatus
    # );

    def control_service(self, service_handle, dwControl):

        lpServiceStatus = SERVICE_STATUS_PROCESS()

        if windll.advapi32.ControlService(service_handle, dwControl, byref(lpServiceStatus)) == 0:
            self.logger.error('Failed to call ControlService')
            return

        return lpServiceStatus

    ###########################################################################
    # Starts a service
    #
    # BOOL WINAPI StartService(
    #   _In_     SC_HANDLE hService,
    #   _In_     DWORD     dwNumServiceArgs,
    #   _In_opt_ LPCTSTR   *lpServiceArgVectors
    # );

    def start_service(self, service_handle):

        if windll.advapi32.StartServiceA(service_handle, 0, 0) == 0:
            self.logger.error('Failed to call StartService')
            return False

        else:
            return True

    ###########################################################################
    # Changes the configuration parameters of a service.
    #
    # BOOL WINAPI ChangeServiceConfig(
    #   _In_      SC_HANDLE hService,
    #   _In_      DWORD     dwServiceType,
    #   _In_      DWORD     dwStartType,
    #   _In_      DWORD     dwErrorControl,
    #   _In_opt_  LPCTSTR   lpBinaryPathName,
    #   _In_opt_  LPCTSTR   lpLoadOrderGroup,
    #   _Out_opt_ LPDWORD   lpdwTagId,
    #   _In_opt_  LPCTSTR   lpDependencies,
    #   _In_opt_  LPCTSTR   lpServiceStartName,
    #   _In_opt_  LPCTSTR   lpPassword,
    #   _In_opt_  LPCTSTR   lpDisplayName
    # );

    def change_service_config(self, service_handle,
                              dwStartType=SERVICE_DISABLED):

        if windll.advapi32.ChangeServiceConfigA(service_handle, SERVICE_NO_CHANGE, dwStartType, SERVICE_NO_CHANGE, 0, 0, 0, 0, 0, 0, 0) == 0:
            self.logger.error('Failed to call ChangeServiceConfig')
            raise WinError(get_last_error())
            return False

        else:
            return True

    def start_service_helper(self, service_name='Dnscache'):

        sc_handle = None
        service_handle = None

        timeout = 5

        sc_handle = self.open_sc_manager()

        if not sc_handle:
            return

        service_handle = self.open_service(sc_handle, service_name)

        if not service_handle:
            self.close_service_handle(sc_handle)
            return

        # Enable the service
        if not self.change_service_config(service_handle, SERVICE_AUTO_START):

            # Backup enable the service
            try:
                subprocess.check_call("sc config %s start= auto" %
                                      service_name, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError, e:
                self.logger.error(
                    'Failed to enable the service %s. (sc config)',
                    service_name)
            else:
                self.logger.debug(
                    'Successfully enabled the service %s. (sc config)',
                    service_name)

        else:
            self.logger.debug('Successfully enabled the service %s.',
                             service_name)

        service_status = self.query_service_status_ex(service_handle)

        if service_status:

            if not service_status.dwCurrentState in [SERVICE_RUNNING, SERVICE_START_PENDING]:

                    # Start service
                if self.start_service(service_handle):

                        # Wait for the service to start
                    while timeout:
                        timeout -= 1
                        time.sleep(1)

                        service_status = self.query_service_status_ex(
                            service_handle)
                        if service_status.dwCurrentState == SERVICE_RUNNING:
                            self.logger.debug(
                                'Successfully started the service %s.', service_name)
                            break
                    else:
                        self.logger.error(
                            'Timed out while trying to start the service %s.', service_name)
                else:
                    self.logger.error(
                        'Failed to start the service %s.', service_name)
            else:
                self.logger.debug(
                    'Service %s is already running.', service_name)

        # As a backup call net stop
        if service_status.dwCurrentState != SERVICE_RUNNING:

            try:
                subprocess.check_call("net start %s" % service_name,
                                      shell=True, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError, e:
                self.logger.error(
                    'Failed to start the service %s. (net stop)', service_name)
            else:
                self.logger.debug('Successfully started the service %s.',
                                 service_name)

        self.close_service_handle(service_handle)
        self.close_service_handle(sc_handle)

    def stop_service_helper(self, service_name='Dnscache'):

        sc_handle = None
        service_handle = None

        Control = SERVICE_CONTROL_STOP
        dwControl = DWORD(Control)
        timeout = 5

        sc_handle = self.open_sc_manager()

        if not sc_handle:
            return

        service_handle = self.open_service(sc_handle, service_name)

        if not service_handle:
            self.close_service_handle(sc_handle)
            return

        # Disable the service
        if not self.change_service_config(service_handle, SERVICE_DISABLED):

            # Backup disable the service
            try:
                subprocess.check_call("sc config %s start= disabled" %
                                      service_name, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError, e:
                self.logger.error(
                    'Failed to disable the service %s. (sc config)', service_name)
            else:
                self.logger.debug(
                    'Successfully disabled the service %s. (sc config)', service_name)

        else:
            self.logger.debug(
                'Successfully disabled the service %s.', service_name)

        service_status = self.query_service_status_ex(service_handle)

        if service_status:

            if service_status.dwCurrentState != SERVICE_STOPPED:

                # Send a stop code to the service
                if self.control_service(service_handle, dwControl):

                    # Wait for the service to stop
                    while timeout:
                        timeout -= 1
                        time.sleep(1)

                        service_status = self.query_service_status_ex(
                            service_handle)
                        if service_status.dwCurrentState == SERVICE_STOPPED:
                            self.logger.debug(
                                'Successfully stopped the service %s.', service_name)
                            break

                    else:
                        self.logger.error(
                            'Timed out while trying to stop the service %s.', service_name)
                else:
                    self.logger.error(
                        'Failed to stop the service %s.', service_name)
            else:
                self.logger.debug(
                    'Service %s is already stopped.', service_name)

        # As a backup call net stop
        if service_status.dwCurrentState != SERVICE_STOPPED:

            try:
                subprocess.check_call("net stop %s" % service_name,
                                      shell=True, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError, e:
                self.logger.error(
                    'Failed to stop the service %s. (net stop)', service_name)
            else:
                self.logger.debug(
                    'Successfully stopped the service %s.', service_name)

        self.close_service_handle(service_handle)
        self.close_service_handle(sc_handle)

    ###########################################################################
    # Process related functions
    ###########################################################################

    ###########################################################################
    # The GetExtendedTcpTable function retrieves a table that contains a list of TCP endpoints available to the application.
    #
    # DWORD GetExtendedTcpTable(
    #  _Out_   PVOID           pTcpTable,
    #  _Inout_ PDWORD          pdwSize,
    #  _In_    BOOL            bOrder,
    #  _In_    ULONG           ulAf,
    #  _In_    TCP_TABLE_CLASS TableClass,
    #  _In_    ULONG           Reserved
    # );

    def get_extended_tcp_table(self):

        dwSize = DWORD(sizeof(MIB_TCPROW_OWNER_PID) * 512 + 4)

        TcpTable = MIB_TCPTABLE_OWNER_PID()

        if windll.iphlpapi.GetExtendedTcpTable(byref(TcpTable), byref(dwSize), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR:
            self.logger.error("Failed to call GetExtendedTcpTable")
            return

        for item in TcpTable.table[:TcpTable.dwNumEntries]:
            yield item

    def _get_pid_port_tcp(self, port):

        for item in self.get_extended_tcp_table():

            lPort = socket.ntohs(item.dwLocalPort)
            lAddr = socket.inet_ntoa(struct.pack('L', item.dwLocalAddr))
            pid = item.dwOwningPid

            if lPort == port:
                return pid
        else:
            return None

    ##########################################################################
    # The GetExtendedUdpTable function retrieves a table that contains a list of UDP endpoints available to the application.
    #
    # DWORD GetExtendedUdpTable(
    #   _Out_   PVOID           pUdpTable,
    #   _Inout_ PDWORD          pdwSize,
    #   _In_    BOOL            bOrder,
    #   _In_    ULONG           ulAf,
    #   _In_    UDP_TABLE_CLASS TableClass,
    #   _In_    ULONG           Reserved
    # );

    def get_extended_udp_table(self):

        dwSize = DWORD(sizeof(MIB_UDPROW_OWNER_PID) * 512 + 4)

        UdpTable = MIB_UDPTABLE_OWNER_PID()

        if windll.iphlpapi.GetExtendedUdpTable(byref(UdpTable), byref(dwSize), False,  AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR:
            self.logger.error("Failed to call GetExtendedUdpTable")
            return

        for item in UdpTable.table[:UdpTable.dwNumEntries]:
            yield item

    def _get_pid_port_udp(self, port):

        for item in self.get_extended_udp_table():

            lPort = socket.ntohs(item.dwLocalPort)
            lAddr = socket.inet_ntoa(struct.pack('L', item.dwLocalAddr))
            pid = item.dwOwningPid

            if lPort == port:
                return pid
        else:
            return None

    ##########################################################################
    # Retrieves the name of the executable file for the specified process.
    #
    # DWORD WINAPI GetProcessImageFileName(
    #   _In_  HANDLE hProcess,
    #   _Out_ LPTSTR lpImageFileName,
    #   _In_  DWORD  nSize
    # );

    def get_process_image_filename(self, pid):

        process_name = None

        if pid == 4:
            # Skip the inevitable errno 87, invalid parameter
            process_name = 'System'
        elif pid:
            hProcess = windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if hProcess:

                lpImageFileName = create_string_buffer(MAX_PATH)

                if windll.psapi.GetProcessImageFileNameA(hProcess, lpImageFileName, MAX_PATH) > 0:
                    process_name = os.path.basename(lpImageFileName.value)
                else:
                    self.logger.error('Failed to call GetProcessImageFileNameA, %d' %
                                      (ctypes.GetLastError()))

                windll.kernel32.CloseHandle(hProcess)

        return process_name

    def setLastErrorNull(self):
        """Workaround for WinDivert handle.send() LastError behavior.

        It looks a lot like WinDivert's handle.send(wdpkt) erroneously fails if
        LastError is non-zero before invoking the method. Hence, in case of ANY
        Windows APIs setting LastError to a nonzero value, this function is
        available for the Windows Diverter to NULL LastError before invoking
        handle.send().

        This was discovered in cases where GetProcessImageFileNameA() was
        called on PID 4 (System): GetProcessImageFileNameA returned an error
        value, and GetLastError() returned 87. Reliably when this happened,
        handle.send(wdpkt) raised an exception that, when printed as a string,
        read as follows:

            [Error 87] The parameter is incorrect.

        In these cases, calling SetLastError(0) before invoking handle.send()
        yielded normal operation.
        """
        ctypes.windll.kernel32.SetLastError(0)

    ##########################################################################
    # The GetAdaptersAddresses function retrieves the addresses associated with the adapters on the local computer.
    #
    # ULONG WINAPI GetAdaptersAddresses(
    #   _In_    ULONG                 Family,
    #   _In_    ULONG                 Flags,
    #   _In_    PVOID                 Reserved,
    #   _Inout_ PIP_ADAPTER_ADDRESSES AdapterAddresses,
    #   _Inout_ PULONG                SizePointer
    # );

    def get_adapters_addresses(self):

        Size = ULONG(0)

        windll.iphlpapi.GetAdaptersAddresses(AF_INET, 0, None, None,
                                             byref(Size))

        AdapterAddresses = create_string_buffer(Size.value)
        pAdapterAddresses = cast(AdapterAddresses,
                                 POINTER(IP_ADAPTER_ADDRESSES))

        if not windll.iphlpapi.GetAdaptersAddresses(AF_INET, 0, None, pAdapterAddresses, byref(Size)) == NO_ERROR:
            self.logger.error('Failed calling GetAdaptersAddresses')
            return

        while pAdapterAddresses:

            yield pAdapterAddresses.contents
            pAdapterAddresses = pAdapterAddresses.contents.Next

    def get_active_ethernet_adapters(self):

        for adapter in self.get_adapters_addresses():

            if adapter.IfType == MIB_IF_TYPE_ETHERNET and adapter.OperStatus == IFOPERSTATUSUP:
                yield adapter

    def check_active_ethernet_adapters(self):

        for adapter in self.get_adapters_addresses():

            if adapter.IfType == MIB_IF_TYPE_ETHERNET and adapter.OperStatus == IFOPERSTATUSUP:
                return True
        else:
            return False

    def get_adapter_friendlyname(self, if_index):

        for adapter in self.get_adapters_addresses():

            if adapter.IfIndex == if_index:
                return adapter.FriendlyName

        else:
            return None

    ###########################################################################
    # The GetAdaptersInfo function retrieves adapter information for the local computer.
    #
    # On Windows XP and later:  Use the GetAdaptersAddresses function instead of GetAdaptersInfo.
    #
    # DWORD GetAdaptersInfo(
    #   _Out_   PIP_ADAPTER_INFO pAdapterInfo,
    #   _Inout_ PULONG           pOutBufLen
    # );

    def get_adapters_info(self):

        OutBufLen = DWORD(0)

        windll.iphlpapi.GetAdaptersInfo(None, byref(OutBufLen))

        AdapterInfo = create_string_buffer(OutBufLen.value)
        pAdapterInfo = cast(AdapterInfo, POINTER(IP_ADAPTER_INFO))

        if not windll.iphlpapi.GetAdaptersInfo(byref(AdapterInfo), byref(OutBufLen)) == NO_ERROR:
            self.logger.error('Failed calling GetAdaptersInfo')
            return

        while pAdapterInfo:

            yield pAdapterInfo.contents
            pAdapterInfo = pAdapterInfo.contents.Next

    def get_gateways(self, adapter):

        gateway = adapter.GatewayList

        while gateway:

            yield gateway.IpAddress.String
            gateway = gateway.Next

    def get_ipaddresses(self, adapter):

        ipaddress = adapter.IpAddressList

        while ipaddress:

            yield ipaddress.IpAddress.String
            ipaddress = ipaddress.Next

    def get_ipaddresses_netmask(self, adapter):

        ipaddress = adapter.IpAddressList

        while ipaddress:

            yield (ipaddress.IpAddress.String, ipaddress.IpMask.String)
            ipaddress = ipaddress.Next

    def get_ipaddresses_index(self, index):

        for adapter in self.get_adapters_info():

            if adapter.Index == index:
                return self.get_ipaddresses(adapter)

    def get_ip_with_gateway(self):

        for adapter in self.get_adapters_info():
            for gateway in self.get_gateways(adapter):
                if gateway != '0.0.0.0':
                    return self.get_ipaddresses(adapter).next()
        else:
            return None

    def check_ipaddresses_interface(self, adapter):

        for ipaddress in self.get_ipaddresses(adapter):
            if ipaddress != '0.0.0.0':
                return True
        else:
            return False

    ###########################################################################
    # The GetNetworkParams function retrieves network parameters for the local computer.
    #
    # DWORD GetNetworkParams(
    #   _Out_ PFIXED_INFO pFixedInfo,
    #   _In_  PULONG      pOutBufLen
    # );

    def get_network_params(self):
        OutBufLen = ULONG(sizeof(FIXED_INFO))
        FixedInfo = FIXED_INFO()

        if not windll.iphlpapi.GetNetworkParams(byref(FixedInfo), byref(OutBufLen)) == NO_ERROR:
            self.logger.error('Failed calling GetNetworkParams')
            return None

        return FixedInfo

    def get_dns_servers(self):

        FixedInfo = self.get_network_params()

        if not FixedInfo:
            return

        ip_addr_string = FixedInfo.DnsServerList

        while ip_addr_string:

            yield ip_addr_string.IpAddress.String
            ip_addr_string = ip_addr_string.Next

    ###########################################################################
    # The GetBestInterface function retrieves the index of the interface that has the best route to the specified IPv4 address.
    #
    # DWORD GetBestInterface(
    #   _In_  IPAddr dwDestAddr,
    #   _Out_ PDWORD pdwBestIfIndex
    # );

    def get_best_interface(self, ip='8.8.8.8'):
        BestIfIndex = DWORD()
        DestAddr = socket.inet_aton(ip)

        if not windll.iphlpapi.GetBestInterface(DestAddr, byref(BestIfIndex)) == NO_ERROR:
            self.logger.error('Failed calling GetBestInterface')
            return None

        return BestIfIndex.value

    def check_best_interface(self, ip='8.8.8.8'):
        BestIfIndex = DWORD()
        DestAddr = socket.inet_aton(ip)

        if not windll.iphlpapi.GetBestInterface(DestAddr, byref(BestIfIndex)) == NO_ERROR:
            return False

        return True

    # Return the best local IP address to reach defined IP address
    def get_best_ipaddress(self, ip='8.8.8.8'):

        index = self.get_best_interface(ip)

        if index != None:
            addresses = self.get_ipaddresses_index(index)
            for address in addresses:
                return address
            else:
                return None
        else:
            return None

    ###########################################################################
    # Convert interface index to name
    #
    # NETIO_STATUS WINAPI ConvertInterfaceIndexToLuid(
    #   _In_  NET_IFINDEX InterfaceIndex,
    #   _Out_ PNET_LUID   InterfaceLuid
    # );
    #
    # NETIO_STATUS WINAPI ConvertInterfaceLuidToNameA(
    #   _In_  const NET_LUID *InterfaceLuid,
    #   _Out_       PSTR     InterfaceName,
    #   _In_        SIZE_T   Length
    # );

    def convert_interface_index_to_name(self, index):

        InterfaceLuid = ULONG64()

        if not windll.iphlpapi.ConvertInterfaceIndexToLuid(index, byref(InterfaceLuid)) == NO_ERROR:
            self.logger.error('Failed calling ConvertInterfaceIndexToLuid')
            return None

        InterfaceName = create_string_buffer(NDIS_IF_MAX_STRING_SIZE + 1)

        if not windll.iphlpapi.ConvertInterfaceLuidToNameA(byref(InterfaceLuid), InterfaceName, NDIS_IF_MAX_STRING_SIZE + 1) == NO_ERROR:
            self.logger.error('Failed calling ConvertInterfaceLuidToName')
            return None

        return InterfaceName.value

    ###########################################################################
    # DnsFlushResolverCache
    #
    # DWORD APIENTRY DhcpNotifyConfigChange(
    #     LPWSTR lpwszServerName,
    #     LPWSTR lpwszAdapterName,
    #     BOOL fIsNewIPAddress,
    #     DWORD dwIPIndex,
    #     DWORD dwIPAddress,
    #     DWORD dwSubnetMask,
    #     int nServiceEnable );

    def notify_ip_change(self, adapter_name):

        if windll.dhcpcsvc.DhcpNotifyConfigChange(0, adapter_name, 0, 0, 0, 0, 0) == NO_ERROR:
            self.logger.debug(
                'Successfully performed adapter change notification on %s', adapter_name)
        else:
            self.logger.error('Failed to notify adapter change on %s',
                              adapter_name)

    ###########################################################################
    # DnsFlushResolverCache
    def flush_dns(self):

        try:
            subprocess.check_call(
                'ipconfig /flushdns', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError, e:
            self.logger.error("Failed to flush DNS cache. Local machine may "
                              "use cached DNS results.")
        else:
            self.logger.debug('Flushed DNS cache.')

    def get_reg_value(self, key, sub_key, value, sam=KEY_READ):

        try:
            handle = OpenKey(key, sub_key, 0, sam)
            [data, regtype] = QueryValueEx(handle, value)
            CloseKey(handle)
            if data == '':
                raise WindowsError

            return data

        except WindowsError:
            self.logger.error('Failed getting registry value %s.', value)
            return None

    def set_reg_value(self, key, sub_key, value, data, type=REG_SZ, sam=KEY_WRITE):

        try:
            handle = CreateKeyEx(key, sub_key, 0, sam)
            SetValueEx(handle, value, 0, type, data)
            CloseKey(handle)

            return True

        except WindowsError:
            self.logger.error('Failed setting registry value %s', value)
            return False

    ###########################################################################
    # Set DNS Server

    def set_dns_server(self, dns_server='127.0.0.1'):

        key = HKEY_LOCAL_MACHINE
        sub_key = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s"
        value = 'NameServer'

        for adapter in self.get_active_ethernet_adapters():

            # Preserve existing setting
            dns_server_backup = self.get_reg_value(key, sub_key %
                                                   adapter.AdapterName, value)

            # Restore previous value or a blank string if the key was not
            # present
            if dns_server_backup:
                self.adapters_dns_server_backup[adapter.AdapterName] = (
                    dns_server_backup, adapter.FriendlyName)
            else:
                self.adapters_dns_server_backup[adapter.AdapterName] = (
                    '', adapter.FriendlyName)

            # Set new dns server value
            if self.set_reg_value(key, sub_key % adapter.AdapterName, value, dns_server):
                self.logger.debug('Set DNS server %s on the adapter: %s',
                                 dns_server, adapter.FriendlyName)
                self.notify_ip_change(adapter.AdapterName)
            else:
                self.logger.error(
                    'Failed to set DNS server %s on the adapter: %s', dns_server, adapter.FriendlyName)

    def restore_dns_server(self):

        key = HKEY_LOCAL_MACHINE
        sub_key = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s"
        value = 'NameServer'

        for adapter_name in self.adapters_dns_server_backup:

            (dns_server,
             adapter_friendlyname) = self.adapters_dns_server_backup[adapter_name]

            # Restore dns server value
            if self.set_reg_value(key, sub_key % adapter_name, value, dns_server):
                self.logger.debug('Restored DNS server %s on the adapter: %s',
                                 dns_server, adapter_friendlyname)
            else:
                self.logger.error(
                    'Failed to restore DNS server %s on the adapter: %s', dns_server, adapter_friendlyname)


def test_process_list():

    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    pid = self._get_pid_port_tcp(135)
    if pid:
        self.logger.info('pid: %d name: %s', pid,
                         self.get_process_image_filename(pid))
    else:
        self.logger.error('failed to get pid for tcp port 135')

    pid = self._get_pid_port_udp(123)
    if pid:
        self.logger.info('pid: %d name: %s', pid,
                         self.get_process_image_filename(pid))
    else:
        self.logger.error('failed to get pid for udp port 123')

    pid = self._get_pid_port_tcp(1234)
    if not pid:
        self.logger.info('successfully returned None for unknown tcp port '
                         '1234')

    pid = self._get_pid_port_udp(1234)
    if not pid:
        self.logger.info('successfully returned None for unknown udp port '
                         '1234')


def test_interfaces_list():

    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    # for adapter in self.get_adapters_addresses():
    # self.logger.info('ethernet: %s enabled: %s index: %d friendlyname: %s name: %s', adapter.IfType == MIB_IF_TYPE_ETHERNET, adapter.OperStatus == IFOPERSTATUSUP, adapter.IfIndex, adapter.FriendlyName, adapter.AdapterName)

    for dns_server in self.get_dns_servers():
        self.logger.info('dns: %s', dns_server)

    for gateway in self.get_gateways():
        self.logger.info('gateway: %s', gateway)

    for adapter in self.get_active_ethernet_adapters():
        self.logger.info('active ethernet index: %s friendlyname: %s name: %s',
                         adapter.IfIndex, adapter.FriendlyName, adapter.AdapterName)


def test_registry_nameserver():

    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    key = HKEY_LOCAL_MACHINE
    sub_key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{cd17d5b5-bf83-44f5-8de7-d988e3db5451}'
    value = 'NameServer'
    data = '127.0.0.1'

    data_tmp = self.get_reg_value(key, sub_key, value)
    self.logger.info('NameServer: %s', data_tmp)

    if self.set_reg_value(key, sub_key, value, data):
        self.logger.info('Successfully set value %s to data %s', value, data)

        data_tmp = self.get_reg_value(key, sub_key, value)
        self.logger.info('Nameserver: %s', data_tmp)
    else:
        self.logger.info('Failed to set value %s to data %s', value, data)

    self.notify_ip_change('{cd17d5b5-bf83-44f5-8de7-d988e3db5451}')

    self.flush_dns()


def test_registry_gateway():

    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    key = HKEY_LOCAL_MACHINE
    sub_key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{cd17d5b5-bf83-44f5-8de7-d988e3db5451}'
    #value = 'NameServer'
    #data = '127.0.0.1'

    if self.get_reg_value(key, sub_key, 'DhcpDefaultGateway'):
        self.logger.info('DefaultGateway is set')

    else:
        ip = self.get_reg_value(key, sub_key, 'Dhcp')
        # self.logger

    self.notify_ip_change('{cd17d5b5-bf83-44f5-8de7-d988e3db5451}')


def test_check_connectivity():

    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    if not self.check_gateways():
        self.logger.warning('No gateways found.')
    else:
        self.logger.info('Gateways PASS')

    if not self.check_active_ethernet_adapters():
        self.logger.warning('No active ethernet adapters found')
    else:
        self.logger.info('Active ethernet PASS')

    if not self.get_best_interface():
        self.logger.warning('No routable interface found.')
    else:
        self.logger.info('Routable interface PASS')

    if not self.check_dns_servers():
        self.logger.warning('No DNS servers configured')
    else:
        self.logger.info('DNS server PASS')


def test_stop_service():

    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    self.stop_service_helper('Dnscache')


def test_start_service():
    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    self.start_service_helper('Dnscache')


def test_get_best_ip():
    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    ipaddress = self.get_best_ipaddress()
    self.logger.info("Best ip address: %s" % ipaddress)

    ipaddress = self.get_ip_with_gateway()
    self.logger.info("IP with gateway address: %s" % ipaddress)


def main():
    pass

    # test_process_list()

    # test_interfaces_list()

    # test_registry_gateway()

    # test_check_connectivity()

    # test_stop_service()
    # test_start_service()

    test_get_best_ip()


if __name__ == '__main__':
    main()
