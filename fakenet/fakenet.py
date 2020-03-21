#!/usr/bin/env python
#
# FakeNet-NG is a next generation dynamic network analysis tool for malware
# analysts and penetration testers.
#
# Original developer: Peter Kacherginsky
# Current developer: FireEye FLARE Team (FakeNet@fireeye.com)

import logging
import logging.handlers

import os
import sys
import time
import netifaces
import threading

from collections import OrderedDict

from optparse import OptionParser,OptionGroup
from ConfigParser import ConfigParser

import platform

from optparse import OptionParser
from collections import namedtuple

###############################################################################
# Listener services
import listeners
from listeners import *

###############################################################################
# FakeNet
###############################################################################

class Fakenet(object):

    def __init__(self, logging_level = logging.INFO):

        self.logger = logging.getLogger('FakeNet')
        self.logger.setLevel(logging_level)

        self.logging_level = logging_level

        # Diverter used to intercept and redirect traffic
        self.diverter = None

        # FakeNet options and parameters
        self.fakenet_config_dir = ''
        self.fakenet_config = dict()

        # Diverter options and parameters
        self.diverter_config = dict()

        # Listener options and parameters
        self.listeners_config = OrderedDict()

        # List of running listener providers
        self.running_listener_providers = list()

    def parse_config(self, config_filename):

        if not config_filename:

            config_filename = os.path.join(os.path.dirname(__file__), 'configs', 'default.ini')

        if not os.path.exists(config_filename):

            config_filename = os.path.join(os.path.dirname(__file__), 'configs', config_filename)

            if not os.path.exists(config_filename):

                self.logger.critical('Could not open configuration file %s',
                                     config_filename)
                sys.exit(1)

        self.fakenet_config_dir = os.path.dirname(config_filename)
        config = ConfigParser()
        config.read(config_filename)

        self.logger.info('Loaded configuration file: %s', config_filename)

        # Parse configuration
        for section in config.sections():

            if section == 'FakeNet':
                self.fakenet_config = dict(config.items(section))

            elif section == 'Diverter':
                self.diverter_config = dict(config.items(section))

            elif config.getboolean(section, 'enabled'):
                self.listeners_config[section] = dict(config.items(section))


        # Expand listeners
        self.listeners_config = self.expand_listeners(self.listeners_config)

    def expand_ports(self, ports_list):
        ports = []
        for i in ports_list.split(','):
            if '-' not in i:
                ports.append(int(i))
            else:
                l,h = map(int, i.split('-'))
                ports+= range(l,h+1)
        return ports

    def expand_listeners(self, listeners_config):

        listeners_config_expanded = OrderedDict()

        for listener_name in listeners_config:

            listener_config = self.listeners_config[listener_name]
            ports = self.expand_ports(listener_config['port'])

            if len(ports) > 1:

                for port in ports:

                    listener_config['port'] = port
                    listeners_config_expanded["%s_%d" % (listener_name, port)] = listener_config.copy()

            else:
                listeners_config_expanded[listener_name] = listener_config

        return listeners_config_expanded

    def start(self):

        if self.fakenet_config.get('diverttraffic') and self.fakenet_config['diverttraffic'].lower() == 'yes':

            if (('networkmode' not in self.diverter_config) or
                    (self.diverter_config['networkmode'].lower() not in
                     ['singlehost', 'multihost', 'auto'])):
                self.logger.critical('Error: You must configure a ' +
                                     'NetworkMode for Diverter, either ' +
                                     'SingleHost, MultiHost, or Auto')
                sys.exit(1)

            # Select platform specific diverter
            platform_name = platform.system()

            iface_ip_info = IfaceIpInfo()

            ip_addrs = dict()
            ip_addrs[4] = iface_ip_info.get_ips([4])
            ip_addrs[6] = iface_ip_info.get_ips([6])
            fn_addr = '0.0.0.0'

            if platform_name == 'Windows':

                # Check Windows version
                if platform.release() in ['2000', 'XP', '2003Server', 'post2003']:
                    self.logger.critical('Error: FakeNet-NG only supports ' +
                                         'Windows Vista+.')
                    self.logger.critical('       Please use the original ' +
                                         'Fakenet for older versions of ' +
                                         'Windows.')
                    sys.exit(1)

                if self.diverter_config['networkmode'].lower() == 'auto':
                    self.diverter_config['networkmode'] = 'singlehost'

                from diverters.windows import Diverter
                self.diverter = Diverter(self.diverter_config, self.listeners_config, ip_addrs, self.logging_level)

            elif platform_name.lower().startswith('linux'):
                if self.diverter_config['networkmode'].lower() == 'auto':
                    self.diverter_config['networkmode'] = 'multihost'

                if self.diverter_config['networkmode'].lower() == 'multihost':
                    if (self.diverter_config['linuxrestrictinterface'].lower()
                            != 'off'):
                        fn_iface = self.diverter_config['linuxrestrictinterface']
                        if fn_iface in iface_ip_info.ifaces:
                            try:
                                # default to first link
                                fn_addr = iface_ip_info.get_ips([4], fn_iface)[0]
                            except LookupError as e:
                                self.logger.error('Couldn\'t get IP for %s' %
                                                  (fn_iface))
                                sys.exit(1)
                        else:
                            self.logger.error(
                                'Invalid interface %s specified. Proceeding '
                                'without interface restriction. Exiting.',
                                fn_iface)
                            sys.exit(1)

                from diverters.linux import Diverter
                self.diverter = Diverter(self.diverter_config, self.listeners_config, ip_addrs, self.logging_level)

            else:
                self.logger.critical(
                    'Error: Your system %s is currently not supported.' %
                    (platform_name))
                sys.exit(1)

        # Start all of the listeners
        for listener_name in self.listeners_config:

            listener_config = self.listeners_config[listener_name]
            listener_config['ipaddr'] = fn_addr
            listener_config['configdir'] = self.fakenet_config_dir
            # Anonymous listener
            if not 'listener' in listener_config:
                self.logger.debug('Anonymous %s listener on %s port %s...',
                                 listener_name, listener_config['protocol'],
                                 listener_config['port'])
                continue

            # Get a specific provider for the listener name
            try:
                listener_module   = getattr(listeners, listener_config['listener'])
                listener_provider = getattr(listener_module, listener_config['listener'])

            except AttributeError as e:
                self.logger.error('Listener %s is not implemented.', listener_config['listener'])
                self.logger.error("%s" % e)

            else:

                listener_provider_instance = listener_provider(
                        listener_config, listener_name, self.logging_level)

                # Store listener provider object
                self.running_listener_providers.append(listener_provider_instance)

                try:
                    listener_provider_instance.start()
                except Exception as e:
                    self.logger.error('Error starting %s listener on port %s:',
                                      listener_config['listener'],
                                      listener_config['port'])
                    self.logger.error(" %s" % e)
                    sys.exit(1)

        # Start the diverter
        if self.diverter:
            self.diverter.start()

        for listener in self.running_listener_providers:

            # Only listeners that implement acceptListeners(listeners)
            # interface receive running_listener_providers
            try:
                listener.acceptListeners(self.running_listener_providers)
            except AttributeError:
                self.logger.debug("acceptListeners() not implemented by Listener %s" % listener.name)

            # Only listeners that implement acceptDiverter(diverter)
            # interface receive diverter
            try:
                listener.acceptDiverter(self.diverter)
            except AttributeError:
                self.logger.debug("acceptDiverter() not implemented by Listener %s" % listener.name)

    def stop(self):

        self.logger.info("Stopping...")

        for running_listener_provider in self.running_listener_providers:
            running_listener_provider.stop()

        if self.diverter:
            self.diverter.stop()


class IfaceIpInfo():
    """Make netifaces queryable via listcomps of namedtuples"""

    IfaceIp = namedtuple('IfaceIp', 'iface ip ver')

    _ver_to_spec = {4: netifaces.AF_INET, 6: netifaces.AF_INET6}
    _valid_ipvers = [4, 6]

    def __init__(self):
        self.ifaces = netifaces.interfaces()
        self.ips = []

        for iface in self.ifaces:
            addrs = netifaces.ifaddresses(iface)
            for ipver in self._valid_ipvers:
                self._tabulate_iface(iface, addrs, ipver)

    def _tabulate_iface(self, iface, addrs, ipver):
        spec = self._ver_to_spec[ipver]
        if spec in addrs:
            for link in addrs[spec]:
                self._tabulate_link(iface, link, ipver)

    def _tabulate_link(self, iface, link, ipver):
        if 'addr' in link:
            addr = link['addr']
            self.ips.append(self.IfaceIp(iface, addr, ipver))

    def get_ips(self, ipvers, iface=None):
        """Return IP addresses bound to local interfaces including loopbacks.

        Parameters
        ----------
        ipvers : list(int)
            IP versions desired (4, 6, or both)
        iface : str or NoneType
            Optional interface to limit the query
        returns:
            list(str): IP addresses as requested
        """
        if not all(ver in self._valid_ipvers for ver in ipvers):
            raise ValueError('Only IP versions 4 and 6 are supported')

        if iface and (iface not in self.ifaces):
            raise ValueError('Unrecognized iface %s' % (iface))

        downselect = [i for i in self.ips if i.ver in ipvers]
        if iface:
            downselect = [i for i in downselect if i.iface == iface]
        return [i.ip for i in downselect]


def main():

    print """
  ______      _  ________ _   _ ______ _______     _   _  _____
 |  ____/\   | |/ /  ____| \ | |  ____|__   __|   | \ | |/ ____|
 | |__ /  \  | ' /| |__  |  \| | |__     | |______|  \| | |  __
 |  __/ /\ \ |  < |  __| | . ` |  __|    | |______| . ` | | |_ |
 | | / ____ \| . \| |____| |\  | |____   | |      | |\  | |__| |
 |_|/_/    \_\_|\_\______|_| \_|______|  |_|      |_| \_|\_____|

                        Version 1.4.11
  _____________________________________________________________
                   Developed by FLARE Team
  _____________________________________________________________
                                               """

    # Parse command line arguments
    parser = OptionParser(usage = "fakenet.py [options]:")
    parser.add_option("-c", "--config-file", action="store",  dest="config_file",
                      help="configuration filename", metavar="FILE")
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose", default=False,
                      help="print more verbose messages.")
    parser.add_option("-l", "--log-file", action="store", dest="log_file")
    parser.add_option("-s", "--log-syslog", action="store_true", dest="syslog",
                      default=False, help="Log to syslog via /dev/log")
    parser.add_option("-f", "--stop-flag", action="store", dest="stop_flag",
                      help="terminate if stop flag file is created")
    # TODO: Rework the way loggers are created and configured by subcomponents
    # to produce the expected result when logging control is asserted at the
    # top level. For now, the setting serves its real purpose which is to ease
    # testing on Linux after modifying logging such that console and file
    # output are not mutually exclusive.
    parser.add_option("-n", "--no-console-output", action="store_true",
                      dest="no_con_out", default=False,
                      help="Suppress console output (for testing on Linux)")

    (options, args) = parser.parse_args()

    logging_level = logging.DEBUG if options.verbose else logging.INFO

    date_format = '%m/%d/%y %I:%M:%S %p'
    logging.basicConfig(format='%(asctime)s [%(name)18s] %(message)s',
                        datefmt=date_format, level=logging_level)
    logger = logging.getLogger('')  # Get the root logger i.e. ''

    if options.no_con_out:
        logger.handlers = []

    if options.log_file:
        try:
            loghandler = logging.StreamHandler(stream=open(options.log_file,
                                                           'a'))
        except IOError:
            print('Failed to open specified log file: %s' % (options.log_file))
            sys.exit(1)
        loghandler.formatter = logging.Formatter(
            '%(asctime)s [%(name)18s] %(message)s', datefmt=date_format)
        logger.addHandler(loghandler)

    if options.syslog:
        platform_name = platform.system()
        sysloghandler = None
        if platform_name == 'Windows':
            sysloghandler = logging.handlers.NTEventLogHandler('FakeNet-NG')
        elif platform_name.lower().startswith('linux'):
            sysloghandler = logging.handlers.SysLogHandler('/dev/log')
        else:
            print('Error: Your system %s is currently not supported.' %
                  (platform_name))
            sys.exit(1)

        # Specify datefmt for consistency, but syslog generally logs the time
        # on each log line, so %(asctime) is omitted here.
        sysloghandler.formatter = logging.Formatter(
            '"FakeNet-NG": {"loggerName":"%(name)s", '
            '"moduleName":"%(module)s", '
            '"levelName":"%(levelname)s", '
            '"message":"%(message)s"}', datefmt=date_format)
        logger.addHandler(sysloghandler)

    fakenet = Fakenet(logging_level)
    fakenet.parse_config(options.config_file)

    if options.stop_flag:
        options.stop_flag = os.path.expandvars(options.stop_flag)
        fakenet.logger.info('Will seek stop flag at %s' % (options.stop_flag))

    fakenet.start()

    try:
        while True:
            time.sleep(1)
            if options.stop_flag and os.path.exists(options.stop_flag):
                fakenet.logger.info('Stop flag found at %s' % (options.stop_flag))
                break

    except KeyboardInterrupt:
        pass

    except:
        e = sys.exc_info()[0]
        fakenet.logger.error("ERROR: %s" % e)

    fakenet.stop()

    # Delete flag only after FakeNet-NG has stopped to indicate completion
    if options.stop_flag and os.path.exists(options.stop_flag):
        os.remove(options.stop_flag)

    sys.exit(0)

if __name__ == '__main__':
    main()
