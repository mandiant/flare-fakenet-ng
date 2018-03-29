class Config(object):
    """Configuration primitives.

    Inherit from or instantiate this class and call configure() when you've got
    a dictionary of configuration values you want to process and query.

    Would be nice to have _expand_cidrlist() so blacklists can specify ranges.
    """

    def __init__(self, config_dict=None, portlists=[]):
        if config_dict is not None:
            self.configure(config_dict, portlists)

    def configure(self, config_dict, portlists=[], stringlists=[]):
        """Parse configuration.

        Does three things:
            1.) Turn dictionary keys to lowercase
            2.) Turn string lists into arrays for quicker access
            3.) Expand port range specifications
        """
        self._dict = dict((k.lower(), v) for k, v in config_dict.iteritems())

        for entry in portlists:
            portlist = self.getconfigval(entry)
            if portlist:
                expanded = self._expand_ports(portlist)
                self.setconfigval(entry, expanded)

        for entry in stringlists:
            stringlist = self.getconfigval(entry)
            if stringlist:
                expanded = [s.strip() for s in stringlist.split(',')]
                self.setconfigval(entry, expanded)

    def reconfigure(self, portlists=[], stringlists=[]):
        """Same as configure(), but allows multiple callers to sequentially
        apply parsing directives for port and string lists.

        For instance, if a base class calls configure() specifying one set of
        port lists and string lists, but a derived class knows about further
        configuration items that will need to be accessed samewise, this
        function can be used to leave the existing parsed data alone and only
        re-parse the new port or string lists into arrays.
        """
        self.configure(self._dict, portlists, stringlists)

    def _expand_ports(self, ports_list):
        ports = []
        for i in ports_list.split(','):
            if '-' not in i:
                ports.append(int(i))
            else:
                l, h = map(int, i.split('-'))
                ports += range(l, h + 1)
        return ports

    def _fuzzy_true(self, value):
        return value.lower() in ['yes', 'on', 'true', 'enable', 'enabled']

    def _fuzzy_false(self, value):
        return value.lower() in ['no', 'off', 'false', 'disable', 'disabled']

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
