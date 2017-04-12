class Config:
    def __init__(self, config_dict=None, portlists=[]):
        if config_dict is not None:
            self.configure(config_dict, portlists)

    def configure(self, config_dict, portlists=[]):
        """Parse configuration.

        Does two things:
            1.) Turn dictionary keys to lowercase
            2.) Expand port range specifications
        """
        self._dict = dict( (k.lower(), v) for k, v in config_dict.iteritems())

        for entry in portlists:
            portlist = self.getconfigval(entry)
            if portlist:
                expanded = self._expand_ports(portlist)
                self.setconfigval(entry, expanded)

    def _expand_ports(self, ports_list):
        ports = []
        for i in ports_list.split(','):
            if '-' not in i:
                ports.append(int(i))
            else:
                l,h = map(int, i.split('-'))
                ports+= range(l,h+1)
        return ports

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

    def getconfigval(self, opt, default=None):
        return self._dict[opt.lower()] if self.is_configured(opt) else default

    def setconfigval(self, opt, obj):
        self._dict[opt.lower()] = obj

