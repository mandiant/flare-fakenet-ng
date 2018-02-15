import threading
import traceback
import pcapy
import logging

from diverters import BaseObject
from diverters.mangler import make_mangler
#TODO: why is this not found?
#from diverters.injector import make_injector
from diverters import condition
from diverters import utils as dutils
from scapy.all import Ether, IP


class TrafficMonitor(BaseObject):
    '''
    A generic traffic monitor to watch network traffic and make decision on
    traffic diversion or forwarding.

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
