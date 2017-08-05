import socket
import datetime

class BannerFactory():
    def banner(self, config, bannerlist):
        banner = config.get('banner', '!generic')
        servername = config.get('servername', socket.gethostname())

        insertions = {'servername': servername, 'tz': 'UTC'}

        if banner.startswith('!'):
            banner = banner[1:]
            banner = bannerlist[banner]

        banner = datetime.datetime.now().strftime(banner)
        banner = banner % insertions
        banner = banner.replace('\\n', '\n').replace('\\t', '\t')

        return banner
