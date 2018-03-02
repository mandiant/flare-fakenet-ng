#!/usr/bin/env python
#
# FakeNet-NG is a next generation dynamic network analysis tool for malware
# analysts and penetration testers.
#
# Developed by Peter Kacherginsky

import logging

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

###############################################################################
# Listener services
import listeners
from listeners import *

###############################################################################
# FakeNet
###############################################################################

class Fakenet():

    def __init__(self, logging_level = logging.INFO):

        self.logger = logging.getLogger('FakeNet')
        self.logger.setLevel(logging_level)

        self.logging_level = logging_level

        # Diverter used to intercept and redirect traffic
        self.diverter = None

        # FakeNet options and parameters
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

                self.logger.error('Could not open configuration file %s', config_filename)
                sys.exit(1)

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
                self.logger.error('Error: You must configure a NetworkMode for Diverter, either SingleHost, MultiHost, or Auto')
                sys.exit(1)

            # Select platform specific diverter
            platform_name = platform.system()

            ip_addrs = dict()
            ip_addrs[4] = get_ips([4])  # Get IPv4 addrs
            ip_addrs[6] = get_ips([6])  # Get IPv6 addrs

            if platform_name == 'Windows':

                # Check Windows version
                if platform.release() in ['2000', 'XP', '2003Server', 'post2003']:
                    self.logger.error('Error: FakeNet-NG only supports Windows Vista+.')
                    self.logger.error('       Please use the original Fakenet for older versions of Windows.')
                    sys.exit(1)

                if self.diverter_config['networkmode'].lower() == 'auto':
                    self.diverter_config['networkmode'] = 'singlehost'
                
                from diverters.windows import Diverter
                self.diverter = Diverter(self.diverter_config, self.listeners_config, ip_addrs, self.logging_level)

            elif platform_name.lower().startswith('linux'):
                if self.diverter_config['networkmode'].lower() == 'auto':
                    self.diverter_config['networkmode'] = 'multihost'

                from diverters.linux import Diverter
                self.diverter = Diverter(self.diverter_config, self.listeners_config, ip_addrs, self.logging_level)

            else:
                self.logger.error('Error: Your system %s is currently not supported.', platform_name)
                sys.exit(1)

        # Start all of the listeners
        for listener_name in self.listeners_config:

            listener_config = self.listeners_config[listener_name]

            # Anonymous listener
            if not 'listener' in listener_config:
                self.logger.info('Anonymous %s listener on %s port %s...', listener_name, listener_config['protocol'], listener_config['port'])
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
                except Exception, e:
                    self.logger.error('Error starting %s listener on port %s:', listener_config['listener'], listener_config['port'])
                    self.logger.error(" %s" % e)

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

def get_ips(ipvers):
    """Return IP addresses bound to local interfaces including loopbacks.
    
    Parameters
    ----------
    ipvers : list
        IP versions desired (4, 6, or both); ensures the netifaces semantics
        (e.g. netiface.AF_INET) are localized to this function.
    """
    specs = []
    results = []

    for ver in ipvers:
        if ver == 4:
            specs.append(netifaces.AF_INET)
        elif ver == 6:
            specs.append(netifaces.AF_INET6)
        else:
            raise ValueError('get_ips only supports IP versions 4 and 6')

    for iface in netifaces.interfaces():
        for spec in specs:
            addrs = netifaces.ifaddresses(iface)
            # If an interface only has an IPv4 or IPv6 address, then 6 or 4
            # respectively will be absent from the keys in the interface
            # addresses dictionary.
            if spec in addrs:
                for link in addrs[spec]:
                    if 'addr' in link:
                        results.append(link['addr'])

    return results

def main():

    print """
  ______      _  ________ _   _ ______ _______     _   _  _____ 
 |  ____/\   | |/ /  ____| \ | |  ____|__   __|   | \ | |/ ____|
 | |__ /  \  | ' /| |__  |  \| | |__     | |______|  \| | |  __ 
 |  __/ /\ \ |  < |  __| | . ` |  __|    | |______| . ` | | |_ |
 | | / ____ \| . \| |____| |\  | |____   | |      | |\  | |__| |
 |_|/_/    \_\_|\_\______|_| \_|______|  |_|      |_| \_|\_____|

                         Version  1.3
  _____________________________________________________________
                         Developed by            
             Peter Kacherginsky and Michael Bailey      
       FLARE (FireEye Labs Advanced Reverse Engineering)       
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
    parser.add_option("-f", "--stop-flag", action="store", dest="stop_flag",
                      help="terminate if stop flag file is created")

    (options, args) = parser.parse_args()

    logging_level = logging.DEBUG if options.verbose else logging.INFO

    if options.log_file:
        logging.basicConfig(format='%(asctime)s [%(name)18s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.INFO, filename=options.log_file)
    else:
        logging.basicConfig(format='%(asctime)s [%(name)18s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.INFO)

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
