
import subprocess as sp
import json
import threading
import logging
import traceback

from diverters import BaseObject, utils as dutils
from expiringdict import ExpiringDict


KEY_PROCESS_BLACKLIST = 'processblacklist'
KEY_PROCESS_WHITELIST = 'processwhitelist'


def make_match_all_condition():
    cond = MatchAllCondition({})
    if not cond.initialize():
        return None
    return cond


def make_forwarder_conditions(listeners_config, cb, is_divert, logger=None, ):
    '''
    Make the conditions for a monitor/forwarder.
    @param  listeners_config        : listener configs, as a dictionary
    @param  cb                      : callback to get proces name from ip packet
    @param  is_divert (True|False)  : The process names are blacklisted/ignored
    @param  logger (OPTIONAL)       : a Logger to use, None to use default
    @return                         : None on error, condition object on success
    '''
    logger = logging.getLogger() if logger is None else logger
    conditions = list()

    for lname, lconfig in listeners_config.iteritems():
        logger.debug('Initializing listener config for %s' % (lname,))

        port_condition = make_listener_port_condition(lconfig, logger)
        if port_condition is None:
            _err = 'Failed to initialize port condition for %s' % (lname,)
            logger.error(_err)
            return None

        blprocs = lconfig.get(KEY_PROCESS_BLACKLIST, '').split(',')
        blprocs = [_.strip() for _ in blprocs]
        if len(blprocs) > 0:
            # if diverting, the process name is blacklisted/ignored
            pnames_cond = make_procnames_condition(blprocs, cb, logger, is_divert)
            if pnames_cond is None:
                return None
            cond = AndCondition({'conditions': [port_condition, pnames_cond]})
            if not cond.initialize():
                _err = 'Failed to make condition for %s config' % (lname,)
                logger.error(_err)
                return None
        conditions.append(cond)

    listener_conditions = OrCondition({'conditions': conditions})
    if not listener_conditions.initialize():
        return None
    return listener_conditions


def make_listener_port_condition(lconfig, logger=None, negate=False):
    '''
    Make the condition for destination port based on a listner config.
    @param lconfig          : dictionary of listener config
    @param logger (OPTIONAL): Logger to use
    @param negate           : Negate the condition, default to False
    @return                 : condition on success, None on error
    '''
    logger = logging.getLogger() if logger is None else logger

    portstring = lconfig.get('port', None)
    if portstring is None:
        return None

    try:
        port = int(portstring)
    except ValueError:
        return None

    pcond = DstPortCondition({'ports': [port], 'not': negate})
    if not pcond.initialize():
        return None
    return pcond


def make_procnames_condition(proc_names, cb, logger=None, negate=False):
    '''
    Make a ProcessNamesCondition with provided names.
    @param proc_names           : comma separated list of process names
    @param cb                   : callback to get proces name from ip packet
    @param logger (OPTIONAL)    : Logger to use,
    @param nagate               : True|False flag, negate the condition
    @return                     : condition on success, None on error
    '''
    logger = logging.getLogger() if logger is None else logger
    procs = [name.strip() for name in proc_names]
    if len(procs) <= 0:
        return None

    cond = ProcessNamesCondition({
            'process_names': procs,
            'process_callback': cb,
            'not': negate})
    if not cond.initialize():
        logger.error('Failed to initialize ProcessNameCondition')
        return None
    return cond


class Condition(BaseObject):
    '''
    This is a generic class to match a network packet against a predefined
    condition. This class expects a dictionary configuration. The following base
    config is supported:
    {
        'not': True,         # negate the rule
        'default_pass': True # default behavior on unexpected input
    }
    '''

    def __init__(self, config):
        super(Condition, self).__init__(config)
        self.negate = self.config.get('not', False)
        self.default = self.config.get('default_pass', False)

    def is_pass(self, ip_packet):
        raise NotImplementedError

class IpCondition(Condition):
    '''
    This class is a condition to match both source and destination IP address
    from an IP packet. The following configuration is supported:
    {
        'addr.inet': [
            '127.0.0.1',
            '8.8.8.8',
        ]
    }
    '''
    def __init__(self, config):
        super(IpCondition, self).__init__(config)
        self.addrs = list()

    def initialize(self):
        if not super(IpCondition, self).initialize():
            return False

        addrs = self.config.get('addr.inet', list())
        if len(addrs) < 0:
            self.logger.error('Bad config: inet.adds')
            return False

        # A set has better performance when it comes to matching
        self.addrs = set(addrs)
        return True

    def is_pass(self, ip_packet):
        '''@override'''
        try:
            rc = ip_packet.src in self.addrs or ip_packet.dst in self.addrs
        except:
            rc = self.default
        return rc if not self.negate else not rc


class IpSrcCondition(IpCondition):
    def is_pass(self, ip_packet):
        '''@override'''
        try:
            rc = ip_packet.src in self.addrs
        except:
            rc = self.default
        return rc if not self.negate else not rc


class IpDstCondition(IpCondition):
    def is_pass(self, ip_packet):
        '''@override'''
        try:
            rc = ip_packet.dst in self.addrs
        except:
            rc = self.default
        return rc if not self.negate else not rc
        

class PortCondition(Condition):
    '''
    This class is a condition to match both source and destination ports.
    The following configuration is supported:
    {
        'ports': [21, '22'],
    }
    '''
    def __init__(self, config):
        super(PortCondition, self).__init__(config)
        self.ports = list()

    def initialize(self):
        if not super(PortCondition, self).initialize():
            return False

        try:
            ports = [int(_) for _ in self.config.get('ports', list())]
        except:
            error = "%s\nInvalid port config" % (traceback.format_exc(),)
            self.logger.error(error)
            return False
        self.ports = set(ports)
        return True

    def is_pass(self, ip_packet):
        '''@override'''
        tport = dutils.tport_from_ippacket(ip_packet)
        if tport is None:
            return self.default
        rc = tport.dport in self.ports or tport.sport in self.ports
        return rc if not self.negate else not rc

class DstPortCondition(PortCondition):
    def is_pass(self, ip_packet):
        '''@override'''
        tport = dutils.tport_from_ippacket(ip_packet)
        if tport is None:
            return self.default
        rc = tport.dport in self.ports
        return rc if not self.negate else not rc


class SrcPortCondition(PortCondition):
    def is_pass(self, ip_packet):
        '''@override'''
        tport = dutils.tport_from_ippacket(ip_packet)
        if tport is None:
            return self.default
        rc = tport.sport in self.ports
        return rc if not self.negate else not rc


class CompoundCondition(Condition):
    '''This class is a compound class, matching multiple conditions.
    The following configuration is supported:
    config = {
        'conditions': [
            cond_obj1, cond_obj2, cond_obj3
        ]
    }
    '''
    def __init__(self, config):
        super(CompoundCondition, self).__init__(config)
        self.conditions = list()

    def initialize(self):
        if not super(CompoundCondition, self).initialize():
            return False

        self.conditions = self.config.get('conditions', list())
        if len(self.conditions) <= 0:
            return False

        for cond in self.conditions:
            if not isinstance(cond, Condition):
                return False

        return True

class AndCondition(CompoundCondition):    
    def is_pass(self, ip_packet):
        '''@override'''
        rc = True
        for cond in self.conditions:
            if not cond.is_pass(ip_packet):
                rc = False
                break
        return rc if not self.negate else not rc


class OrCondition(CompoundCondition):
    def is_pass(self, ip_packet):
        rc = False
        for cond in self.conditions:
            if cond.is_pass(ip_packet):
                rc = True
                break
        return rc if not self.negate else not rc


class MatchAllCondition(Condition):
    '''This class match all packts. No configuration is required'''
    def is_pass(self, ip_packet):
        '''@override'''
        return True


class MatchNoneCondition(Condition):
    '''This class match none of the packets. No configuration is required'''
    def is_pass(self, ip_packet):
        '''@override'''
        return False



class ProcessNamesCondition(Condition):
    '''
    This condition match network traffic generated by specific procss names.
    This condition starts a new background dtrace procses to monitor network
    and processes. The following configuration is supported:
    {
        'process_names': [
            'nc',                   # netcat
            'com.apple.WebKit',     # safari
        ],
        'process_callback': callback_function
    }
    '''
    def initialize(self):
        if not super(ProcessNamesCondition, self).initialize():
            return False
        
        self.proc_names = self.config.get('process_names', None)
        if self.proc_names is None or len(self.proc_names) <= 0:
            self.logger.error('Bad process names')
            return False

        self.cb = self.config.get('process_callback', None)
        if self.cb is None:
            return False
        return True
    
    def is_pass(self, ip_packet):
        procname = self.cb(ip_packet)
        rc = procname in self.proc_names
        return rc if not self.negate else not rc