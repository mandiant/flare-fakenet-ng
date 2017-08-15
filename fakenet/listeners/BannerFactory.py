import random
import socket
import string
import datetime

class Banner():
    """Act like a string, but actually get date/time components on the fly."""

    def __init__(self, banner, insertions):
        self.banner = banner
        self.insertions = insertions
        # Indicate an error in the banner early-on as opposed to
        # when a login or other event occurs.
        test = self.failEarly()

    def failEarly(self):
        """Raise exceptions upon construction rather than later."""
        return self.fmt()

    def __len__(self):
        """Needed for pyftpdlib.
        
        If the length changes between the time when the caller obtains the
        length and the time when they reference the string, then... *shrug*?
        """
        return len(self.fmt())

    def __repr__(self):
        return self.fmt()

    def fmt(self):
        banner = self.banner
        banner = datetime.datetime.now().strftime(banner)
        banner = banner % self.insertions
        banner = banner.replace('\\n', '\n').replace('\\t', '\t')
        return banner

class BannerFactory():
    def genBanner(self, config, bannerdict, defaultbannerkey='!generic'):
        """Select and format a banner.
        
        Supported banner escapes:
            !<key> - Use the banner whose key in bannerdict is <key>
            !random - Use a random banner from bannerdict
            !generic - Every listener supporting banners must have a generic

        Banners can include literal '\n' or '\t' tokens (slash followed by the
        letter n or t) to indicate that a newline or tab should be inserted.

        Banners can include %(servername)s or %(tz)s to insert the servername
        or time zone (hard-coded to 'UTC' as of this writing).

        If the user does not specify a banner, then '!generic' is used by
        default, resulting in bannerdict['generic'] being used. If the user
        specifies a bang escape e.g. '!iis-6', then the banner keyed by that
        name will be used. If the user specifies '!random' then a random banner
        will be chosen from bannerdict.

        Because some banners include the servername as an insertion string,
        this method also retrieves that configuration value and incorporates
        a couple of similar escape sequences:
            !random - Randomized servername with random length between 1-15
            !gethostname - Use the real hostname
        """

        banner = config.get('banner', defaultbannerkey)
        servername = config.get('servername', 'localhost')

        if servername.startswith('!'):
            servername = servername[1:]
            if servername.lower() == 'random':
                servername = self.randomizeHostname()
            elif servername.lower() == 'gethostname':
                servername = socket.gethostname()
            else:
                raise ValueError('ServerName config invalid escape: !%s' %
                        (servername))

        if banner.startswith('!'):
            banner = banner[1:]
            if banner.lower() == 'random':
                banner = random.choice(bannerdict.keys())
            elif banner not in bannerdict:
                raise ValueError('Banner config escape not a valid banner key')

            banner = bannerdict[banner]

        insertions = {'servername': servername, 'tz': 'UTC'}

        return Banner(banner, insertions)

        # banner = datetime.datetime.now().strftime(banner)
        # banner = banner % insertions
        # banner = banner.replace('\\n', '\n').replace('\\t', '\t')
        # return banner

    def randomizeHostname(self):
        valid_hostname_charset = (string.ascii_letters + string.digits + '-')
        n = random.randint(1, 15)
        return ''.join(random.choice(valid_hostname_charset) for _ in range(n))
