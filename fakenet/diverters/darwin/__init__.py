
import logging
import os
import netifaces
from diverters.diverterbase import DiverterBase
from diverters.darwin import utils as dutils

class DarwinDiverter(DiverterBase):
    def __init__(self, diverter_config, listeners_config, ip_addrs,
                 logging_level=logging.INFO):
        super(DarwinDiverter, self).__init__(diverter_config, listeners_config,
                                             ip_addrs, logging_level)
        
        self.gw = None
        self.iface = None
        self.pid = os.getpid()
            
    def __del__(self):
        self.stopCallback()
    
    def initialize(self):
        self.gw = dutils.get_gateway_info()
        if self.gw is None:
            raise NameError("Failed to get gateway")

        self.iface = dutils.get_iface_info(self.gw.get('iface'))
        if self.iface is None:
            raise NameError("Failed to get public interface")
        
        return
    

    #--------------------------------------------------------------
    # implements various DarwinUtilsMixin methods
    #--------------------------------------------------------------

    def check_active_ethernet_adapters(self):
        return len(netifaces.interfaces()) > 0
    
    def check_ipaddresses(self):
        return True
        
    def check_dns_servers(self):
        return True

    def check_gateways(self):
        return len(netifaces.interfaces()) > 0