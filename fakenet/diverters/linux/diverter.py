
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

from expiringdict import ExpiringDict
from diverters import utils
from collections import namedtuple
from netfilterqueue import NetfilterQueue
from diverters.linux.utils import *
from diverters.linux import utils as lutils
from diverters.linux.nfqueue import make_nfqueue_monitor

from diverters.mangler import make_mangler

from diverters import constants
from diverters import DiverterBase
from diverters import condition


def make_diverter(dconf, lconf, loglevel):
    config = {
        'diverter_config': dconf,
        'listeners_config': lconf,
        'log_level': loglevel,
    }
    diverter = Diverter(config)
    if not diverter.initialize():
        return None
    return diverter



class LinuxProcessResolver(condition.ProcessResolver):
    '''
    @implements ProcessResolver to resolve process name and process ID from
    an ip_packet. This class is used in ProcessNameCondition.
    '''
    def get_process_name_from_ip_packet(self, ip_packet):
        return lutils.get_procname_from_ip_packet(ip_packet)



class Diverter(DiverterBase):
    '''
    Linux implementation for the Diverter class.
    '''
    CACHE_MAX_LENGTH = 0xfff
    CACHE_MAX_AGE_SECONDS = 120

    def __init__(self, config):
        super(Diverter, self).__init__(config)
        self._current_iptables_rules = None
        self._old_dns = None

        self.ip_addrs = utils.get_ip_addresses(logger=self.logger)

        # Execute command list
        self.port_execute = dict()

        self.monitors = list()

    def initialize(self):
        if not super(Diverter, self).initialize():
            return False
        
        # Check active interfaces
        if not lutils.check_active_ethernet_adapters():
            self.logger.error('WARNING: No active ethernet interfaces ' +
                              'detected!')
            self.logger.error('         Please enable a network interface.')
            return False

        # Check configured gateways
        if not lutils.check_gateways():
            self.logger.error('WARNING: No gateways configured!')
            self.logger.error('         Please configure a default ' +
                              'gateway or route in order to intercept ' +
                              'external traffic.')
            return False

        # Check configured DNS servers
        if not lutils.check_dns_servers():
            self.logger.warning('WARNING: No DNS servers configured!')
            self.logger.warning('         Please configure a DNS server in ' +
                                'order to allow network resolution.')


        if not self._parse_listeners_config():
            return False

        if not self.check_privileged():
            self.logger.error('The Linux Diverter requires administrative ' +
                              'privileges')
            return False

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

        # Track iptables rules not associated with any nfqueue object
        self.rules_added = []
        self.ip_fwd_table = ExpiringDict(self.CACHE_MAX_LENGTH,
                                         self.CACHE_MAX_AGE_SECONDS)

        if not self.__initialize_monitors():
            return False
        return True
    


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
 
        for m in self.monitors:
            if not m.start():
                self.logger.error('Failed to start monitor')
                return False

        return True

    def stop(self):
        self.logger.info('Stopping Linux Diverter...')

        for m in self.monitors:
            m.signal_stop()

        lutils.remove_iptables_rules(self.rules_added)

        for m in self.monitors:
            m.stop()

        self.logger.info('Stopped Linux Diverter')

        if self.single_host_mode and self.diverter_config.get('modifylocaldns', None):
            lutils.restore_local_dns(self._old_dns)

        lutils.restore_iptables(self._current_iptables_rules)
        return True
    
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
                if not 'protocol' in listener_config:
                    self.logger.error('ERROR: Protocol not defined for ' +
                                      'listener %s', listener_name)
                    return False

                protocol = listener_config['protocol'].upper()
                if not protocol in ['TCP', 'UDP']:
                    self.logger.error('ERROR: Invalid protocol %s for ' +
                                      'listener %s', protocol, listener_name)
                    return False

                ###############################################################
                # Process filtering configuration
                if 'processwhitelist' in listener_config and 'processblacklist' in listener_config:
                    self.logger.error('ERROR: Listener can\'t have both ' +
                                      'process whitelist and blacklist.')
                    return False


                ###############################################################
                # Host filtering configuration
                if 'hostwhitelist' in listener_config and 'hostblacklist' in listener_config:
                    self.logger.error('ERROR: Listener can\'t have both ' +
                                      'host whitelist and blacklist.')
                    return False


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


    def __make_input_monitor(self, qno):
        '''
        Make a network monitor to monitor the INPUT queue.
        @param qno  :   Available queue number for the INPUT queue
        @return     :   None on error, an NfQueueMonitor object on success  
        ''' 
        conds = self.__make_incoming_conditions()
        if conds is None:
            return None
        mangler_config = {
            'ip_forward_table': self.ip_fwd_table,
            'type': 'SrcIpFwdMangler',
        }
        mangler = make_mangler(mangler_config)
        if mangler is None:
            return None
        
        return make_nfqueue_monitor(qno, 'INPUT', 'mangle', conds, mangler)
    

    def __make_output_monitor(self, qno):
        '''
        Make a network monitor to monitor the OUTPUT queue.
        @param qno  :   Available queue number for the INPUT queue
        @return     :   None on error, an NfQueueMonitor object on success
        '''
        conds = self.__make_outgoing_conditions()
        if conds is None:
            return None

        mangler_config  = {
            'ip_forward_table': self.ip_fwd_table,
            'type': 'DstIpFwdMangler',
            'inet.dst': '127.0.0.1',
        }
        mangler = make_mangler(mangler_config)
        if mangler is None:
            return None

        return make_nfqueue_monitor(qno, 'OUTPUT', 'raw', conds, mangler)


    def __initialize_monitors(self):
        nhooks = 2  # INPUT and OUTPUT chains

        qnos = lutils.get_next_nfqueue_numbers(nhooks)
        if len(qnos) != nhooks:
            self.logger.error('Could not procure a sufficient number of ' +
                              'netfilter queue numbers')
            return False                          
        self.monitors = list()

        imon = self.__make_input_monitor(qnos[0])
        if imon is None:
            self.logger.error('Failed to initialize INPUT queue monitor')
            return False
        omon = self.__make_output_monitor(qnos[1])
        if omon is None:
            self.logger.error('Failed to initialize OUTPUT queue monitor')
            return False
        
        self.monitors = [imon, omon]
        return True


    def __make_outgoing_conditions(self):
        '''
        Make a list of conditions that must be matched for out-going packets to
        be filtered/diverted.
        '''
        conditions = list()

        # 1. IpDstCondition: Traffic is not sending to one of my IPs
        ipaddrs = self.ip_addrs
        cond = condition.IpDstCondition({'addr.inet': ipaddrs, 'not': True})
        if not cond.initialize():
            return None
        
        conditions.append(cond)

        # 2. Make listeners conditions
        lconf = self.listeners_config
        resolver = LinuxProcessResolver({})
        resolver.initialize()
        is_divert = True
        logger = self.logger
        conds = condition.make_forwarder_conditions(lconf, resolver, is_divert, logger)
        conditions.append(conds)

        return conditions


    def __make_incoming_conditions(self):
        '''
        Make a list of conditions to be matched before an IP packet is mangled.
        If within single mode, all IP packets must be mangled. 
        If within multihost mode, only match packets NOT directed at us.
        '''
        if self.single_host_mode:
            return [condition.make_match_all_condition()]

        conditions = list()

        # 1. IpDstCondition to not be part of myself:
        #ipaddrs = self.config.get('ip_addrs')[4]
        ipaddrs = self.ip_addrs
        cond = condition.IpDstCondition({'addr.inet': ipaddrs, 'not': True})
        if not cond.initialize():
            return None
        
        conditions.append(cond)
        return conditions
