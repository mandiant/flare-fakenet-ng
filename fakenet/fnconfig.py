class Config:
    def __init__(self, config_dict=None):
        # Copy dictionary with lowercase keys
        if config_dict:
            self.configure(config_dict)

    def configure(self, config_dict):
        self._dict = dict( (k.lower(), v) for k, v in config_dict.iteritems())

    def _fuzzy_true(self, value):
        return value.lower() in ['on', 'true', 'yes']

    def _fuzzy_false(self, value):
        return not self._fuzzy_true(value)

    def is_configured(self, opt):
        return opt.lower() in self._dict.keys()

    def is_unconfigured(self, opt):
        return not self.is_configured(opt)

    def is_set(self, opt):
        return (self.is_configured(opt) and
                self._fuzzy_true(self._dict[opt.lower()]))

    def is_clear(self, opt):
        return (self.is_configured(opt) and
                self._fuzzy_false(self._dict[opt.lower()]))

    def configval(self, opt, default=None):
        return self._dict[opt.lower()] if self.is_configured(opt) else default
