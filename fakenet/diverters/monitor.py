import threading
import traceback
import pcapy
import logging

from diverters import BaseObject
from diverters.mangler import make_mangler
from diverters.injector import make_injector
from diverters import condition
from diverters import utils as dutils
from scapy.all import Ether, IP



def make_monitor(config, logger=None):
    '''
    Make an interface monitor. The following configuration are supported:

    config = {
        'listeners_config': {
            'listeners': <listeners configuration>,
            'addr.inet': 192.168.1.2            # Source IP address to match
            'process_callback': callback        # Callback to get process name
        },

        # Mangler config, other than types, other settings may be optional
        'mangler_config': {
            'type': 'DlinkPacketMangler',
            'dlink.src': <source MAC addr>,
            'dlink.dst': <destination MAC addr>,
            'inet.src':  <source IP addr>,
            'inet.dst':  <destination IP addr>,
        },

        'injector_config': {
            'iface': 'en0'                  # interface to inject traffic into
        },

        'iface': 'en0',                     # name of the interface to monitor
        'is_loopback': True|False           # If iface is a loopback interface
        'is_forwarder': Ture|False          # Does this forward traffic?
    }

    TODO: Instead of 'is_loopback' config, try to detect it by 'iface' name

    @param config:  a configuration dictionary
    @param logger:  optional logger
    @return      :  None on error, a monitor object on success
    '''

    logger = logging.getLogger() if logger is None else logger

    monitor_config = dict()
    is_loopback = config.get('is_loopback', None)
    if is_loopback is None:
        logger.error('Bad monitor config: is_loopback keyword required')
        return None

    is_forwarder = config.get('is_forwarder', None)
    if is_forwarder is None:
        logger.error('Bad monitor config: is_forwarder keyword required')
        return None

    # 1. make conditions for a public monitor/forwarder
    lconfig = config.get('listeners_config', dict()).get('listeners', dict())
    ipconf = config.get('listeners_config', dict()).get('ipconf', None)
    cb = config.get('listeners_config', dict()).get('process_callback', None)
    if cb is None:
        logger.error('process_callback option is required')

    conditions = list()

    if ipconf is not None:
        ipcond = condition.IpSrcCondition(ipconf)
        if not ipcond.initialize():
            logger.error('Failed to make IpSrcCondition')
            return None
        conditions.append(ipcond)

    if is_forwarder:
        is_divert = config.get('is_divert', None)
        if is_divert is None and is_forwarder:
            logger.error('Bad monitor config: is_divert keyword required')
            return None

        conds = condition.make_forwarder_conditions(lconfig, cb, is_divert, logger)
        if conds is None:
            logger.error('Failed to make listener conditions for forwarder')
            return None
        conditions.append(conds)

    if len(conditions) <= 0:
        logger.error('Bad config: No conditions')
        return None

    monitor_config['conditions'] = conditions


    # 2. make a mangler
    mconfig = config.get('mangler_config', dict())
    mangler = make_mangler(mconfig)
    if mangler is None:
        logger.error('Failed to make mangler for monitor')
        return None

    monitor_config['mangler'] = mangler

    # 3. make an injector
    iconfig = config.get('injector_config', dict())
    injector = make_injector(iconfig)
    if injector is None:
        logger.error('Failed to make injector for monitor')
        return None
    monitor_config['forwarder'] = injector

    monitor_config['iface'] = config.get('iface', None)
    if is_loopback:
        monitor = LoopbackInterfaceMonitor(monitor_config)
    else:
        monitor = InterfaceMonitor(monitor_config)

    if not monitor.initialize():
        logger.error('Failed to initialize InterfaceMonitor')
        return None

    return monitor


class TrafficMonitor(BaseObject):
    '''
    A generic traffic monitor to watch network traffic and make decision on
    traffic diversion or forarding.

    The following config is supported:
    config = {
        'type': <MonitorType>,
        'conditions': [
            condition_object0,
            condition_object1,
        ],
        'mangler': <mangler_object>
    }
    '''
    def __init__(self, config):
        super(TrafficMonitor, self).__init__(config)
        self.conditions = None
        self.mangler = None
        self._stopflag = False

    def initialize(self):
        if not super(TrafficMonitor, self).initialize():
            return False

        self.mangler = self.config.get('mangler', None)
        if self.mangler is None:
            self.logger.error('Bad config: mangler is required')
            return False

        self.conditions = self.config.get('conditions', None)
        if self.conditions is None:
            self.logger.error('Bad config: conditions are required')
            return False

        return True

    def is_mangle(self, ip_packet):
        for cond in self.conditions:
            if not cond.is_pass(ip_packet):
                return False
        return True
        
    def start(self):
        return True

    def stop(self):
        return True
    
    def signal_stop(self):
        self._stopflag = True
        return True
    
    def is_running(self):
        return not self._stopflag