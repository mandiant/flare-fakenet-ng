
import logging
from diverters import utils

class BaseObject(object):
    _logger = None
    _config = None

    def __init__(self, config):
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
    _diverter_config = None
    _listeners_config = None
    
    def initialize(self):
        if not super(DiverterBase, self).initialize():
            return False
        
        self.diverter_config = self.config.get('diverter_config', None)
        if self.diverter_config is None:
            self.logger.critical('Bad diverter config')
            return False
        
        lc = self.config.get('listeners_config', None)
        self.lc = utils.parse_listeners_config(lc, self.logger)
        self.listeners_config = lc
        if self.listeners_config is None:
            self.logger.critical('Bad listeners config')
            return False
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