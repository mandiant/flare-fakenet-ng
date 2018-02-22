
import logging
from diverters import utils
import time
import dpkt

class BaseObject(object):
    print("BaseObject()")
    _logger = None
    _config = None

    def __init__(self, config):
        print("BaseObject() __init__(). config:%s\n" % config)
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(self.config.get('log_level', logging.INFO))
    
    def initialize(self):
        return True
    
    # --------------------------------------------------------------------------
    # property stuffs
    # --------------------------------------------------------------------------
    def get_logger(self):
        return self._logger
    
    def set_logger(self, logger):
        self._logger = logger
    
    def get_config(self):
        return self._config
    
    def set_config(self, config):
        self._config = config
    
    logger = property(get_logger, set_logger, None, None)
    config = property(get_config, set_config, None, None)



class DiverterBase(BaseObject):
    print("DiverterBase()")
    _diverter_config = None
    _listeners_config = None
    
    def initialize(self):
        print("DiverterBase() initialize()")
        if not super(DiverterBase, self).initialize():
            return False
        
        self.diverter_config = self.config.get('diverter_config', None)
        if self.diverter_config is None:
            self.logger.critical('Bad diverter config')
            return False
        
        lc = self.config.get('listeners_config', None)
        self.listeners_config = utils.parse_listeners_config(lc, self.logger)
        #self.listeners_config = lc
        if self.listeners_config is None:
            self.logger.critical('Bad listeners config')
            return False

        if self.diverter_config.get('dumppackets').lower() is not None:
            print("setting up pcap\n")
            self.pcap_filename = '%s_%s.pcap' % (self.diverter_config.get(
                'dumppacketsfileprefix', 'packets'),
                time.strftime('%Y%m%d_%H%M%S'))
            self.logger.info('Capturing traffic to %s' % self.pcap_filename)
            self.pcap = dpkt.pcap.Writer(open(self.pcap_filename, 'wb'),
                linktype=dpkt.pcap.DLT_RAW)
            print("pcap setup complete\n")
            #self.pcap_lock = threading.Lock()

        return True
    # --------------------------------------------------------------------------
    # property stuffs
    # --------------------------------------------------------------------------
    def get_diverter_config(self):
        return self._diverter_config
    
    def set_diveter_config(self, dconf):
        self._diverter_config = dconf
    
    def get_listeners_config(self):
        return self._listeners_config
    
    def set_listeners_config(self, lconf):
        self._listeners_config = lconf
    
    diverter_config = property(get_diverter_config, set_diveter_config)
    listeners_config = property(get_listeners_config, set_listeners_config)
