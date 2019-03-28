import logging

import os
import sys

import threading
import SocketServer

import ssl
import socket

from . import *

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.filesystems import AbstractedFS
from pyftpdlib.servers import ThreadedFTPServer

import BannerFactory

FAKEUSER = 'FAKEUSER'
FAKEPWD  = 'FAKEPWD'


EXT_FILE_RESPONSE = {
    '.html': u'FakeNet.html',
    '.png' : u'FakeNet.png',
    '.ico' : u'FakeNet.ico',
    '.jpeg': u'FakeNet.jpg',
    '.exe' : u'FakeNetMini.exe',
    '.pdf' : u'FakeNet.pdf',
    '.xml' : u'FakeNet.html',
    '.txt' : u'FakeNet.txt',
}

# Adapted from various sources including https://github.com/turbo/openftp4
BANNERS = {
    'generic': '{servername} FTP Server',
    'ncftpd': '{servername} NcFTPD Server (licensed copy) ready.',
    'unspec1': lambda hostname: 'FTP server ready',
    'unspec2': lambda hostname: 'FTP server ready %s',
    'iis': lambda hostname: '%s Microsoft FTP Service',
    'iis': lambda hostname: '%s Microsoft FTP Service',
    'iis-3.0': lambda hostname: '%s Microsoft FTP Service (Version 3.0)',
    'iis-4.0': lambda hostname: '%s Microsoft FTP Service (Version 4.0)',
    'iis-5.0': lambda hostname: '%s Microsoft FTP Service (Version 5.0)',
    'iis-6.0': lambda hostname: '%s Microsoft FTP Service (Version 6.0)',
    'vs-2.0.7': lambda hostname: '(vsFTPd 2.0.7)',
    'vs-2.1.0': lambda hostname: '(vsFTPd 2.1.0)',
    'vs-2.1.2': lambda hostname: '(vsFTPd 2.1.2)',
    'vs-2.1.2': lambda hostname: '(vsFTPd 2.1.2)',
    'vs-2.2.0': lambda hostname: '(vsFTPd 2.2.0)',
    'vs-2.2.1': lambda hostname: '(vsFTPd 2.2.1)',
    'vs-2.2.2': lambda hostname: '(vsFTPd 2.2.2)',
    'vs-2.3.0': lambda hostname: '(vsFTPd 2.3.0)',
    'vs-2.3.1': lambda hostname: '(vsFTPd 2.3.1)',
    'vs-2.3.2': lambda hostname: '(vsFTPd 2.3.2)',
    'vs-2.3.4': lambda hostname: '(vsFTPd 2.3.4)',
    'vs-2.3.5': lambda hostname: '(vsFTPd 2.3.5)',

    'wu-2.4(1)': '{servername} (Version wu-2.4(1) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.4(2)': '{servername} (Version wu-2.4(2) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.4(20)': '{servername} (Version wu-2.4(20) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.4.2-academ(1)': '{servername} (Version wu-2.4.2-academ (1) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.4.2-academ[BETA-15](1)': '{servername} (Version wu-2.4.2-academ[BETA-15](1) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.4.2-academ[BETA-16](1)': '{servername} (Version wu-2.4.2-academ[BETA-16](1) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.4.2-academ[BETA-18](1)': '{servername} (Version wu-2.4.2-academ[BETA-18](1) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.4.2-academ[BETA-9](1)': '{servername} (Version wu-2.4.2-academ[BETA-9](1) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.4.2-VR16(1)': '{servername} (Version wu-2.4.2-VR16(1) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.4.2-VR17(1)': '{servername} (Version wu-2.4.2-VR17(1) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.4(3)': '{servername} (Version wu-2.4(3) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.4(4)': '{servername} (Version wu-2.4(4) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.4(6)': '{servername} (Version wu-2.4(6) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.5.0(1)': '{servername} (Version wu-2.5.0(1) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.0(1)': '{servername} (Version wu-2.6.0(1) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.0(2)': '{servername} (Version wu-2.6.0(2) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.0(4)': '{servername} (Version wu-2.6.0(4) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.0(5)': '{servername} (Version wu-2.6.0(5) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.0(7)': '{servername} (Version wu-2.6.0(7) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1-0.6x.21': '{servername} (Version wu-2.6.1-0.6x.21 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1(1)': '{servername} (Version wu-2.6.1(1) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1(12)': '{servername} (Version wu-2.6.1(12) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1-16': '{servername} (Version wu-2.6.1-16 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1-16.7x.1': '{servername} (Version wu-2.6.1-16.7x.1 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1-18': '{servername} (Version wu-2.6.1-18 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1(2)': '{servername} (Version wu-2.6.1(2) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1-20': '{servername} (Version wu-2.6.1-20 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1-21': '{servername} (Version wu-2.6.1-21 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1-23.2': '{servername} (Version wu-2.6.1-23.2 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1-24': '{servername} (Version wu-2.6.1-24 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1-24.1': '{servername} (Version wu-2.6.1-24.1 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.1(3)': '{servername} (Version wu-2.6.1(3) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2(1)': '{servername} (Version wu-2.6.2(1) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2(11)': '{servername} (Version wu-2.6.2(11) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2-11.1204.1ubuntu': '{servername} (Version wu-2.6.2-11.1204.1ubuntu %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2-11.71.1': '{servername} (Version wu-2.6.2-11.71.1 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2-11.72.1': '{servername} (Version wu-2.6.2-11.72.1 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2-11.73.1': '{servername} (Version wu-2.6.2-11.73.1 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2-11.73.1mdk': '{servername} (Version wu-2.6.2-11.73.1mdk %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2-12': '{servername} (Version wu-2.6.2-12 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2-12.1.co5.PROX': '{servername} (Version wu-2.6.2-12.1.co5.PROX %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2-12.rhel2': '{servername} (Version wu-2.6.2-12.rhel2 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2(13)': '{servername} (Version wu-2.6.2(13) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2.1(5)': '{servername} (Version wu-2.6.2.1(5) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2(15)': '{servername} (Version wu-2.6.2(15) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2-15.7x.legacy': '{servername} (Version wu-2.6.2-15.7x.legacy %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2-15.7x.PROX': '{servername} (Version wu-2.6.2-15.7x.PROX %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2(16)': '{servername} (Version wu-2.6.2(16) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2(2)': '{servername} (Version wu-2.6.2(2) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2(3)': '{servername} (Version wu-2.6.2(3) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2(4)': '{servername} (Version wu-2.6.2(4) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2-468': '{servername} (Version wu-2.6.2-468 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2(47)': '{servername} (Version wu-2.6.2(47) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2(48)': '{servername} (Version wu-2.6.2(48) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2-5': '{servername} (Version wu-2.6.2-5 %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2(5)': '{servername} (Version wu-2.6.2(5) %a %b %d %H:%M:%S {tz} %Y) ready.',
    'wu-2.6.2(52)': '{servername} (Version wu-2.6.2(52) %a %b %d %H:%M:%S {tz} %Y) ready.',

    'ws_ftp-2.0.4': '{servername} V2 WS_FTP Server 2.0.4 (0)',
    'ws_ftp-3.1.3': '{servername} V2 WS_FTP Server 3.1.3 (0)',
    'ws_ftp-5.0.5': '{servername} V2 WS_FTP Server 5.0.5 (0)',
    'ws_ftp-7.5.1': '{servername} V2 WS_FTP Server 7.5.1(0)',
    'ws_ftp-7.7': '{servername} V2 WS_FTP Server 7.7(0)',
    'ws_ftp-1.0.3 ': '{servername} X2 WS_FTP Server 1.0.3 (0)',
    'ws_ftp-1.0.5 ': '{servername} X2 WS_FTP Server 1.0.5 (0)',
    'ws_ftp-2.0.0 ': '{servername} X2 WS_FTP Server 2.0.0 (0)',
    'ws_ftp-2.0.3 ': '{servername} X2 WS_FTP Server 2.0.3 (0)',
    'ws_ftp-3.00 ': '{servername} X2 WS_FTP Server 3.00 (0)',
    'ws_ftp-3.1.3 ': '{servername} X2 WS_FTP Server 3.1.3 (0)',
    'ws_ftp-4.0.0 ': '{servername} X2 WS_FTP Server 4.0.0 (0)',
    'ws_ftp-4.0.2 ': '{servername} X2 WS_FTP Server 4.0.2 (0)',
    'ws_ftp-5.0.0 ': '{servername} X2 WS_FTP Server 5.0.0 (0)',
    'ws_ftp-5.0.2 ': '{servername} X2 WS_FTP Server 5.0.2 (0)',
    'ws_ftp-5.0.4 ': '{servername} X2 WS_FTP Server 5.0.4 (0)',
    'ws_ftp-5.0.5 ': '{servername} X2 WS_FTP Server 5.0.5 (0)',
    'ws_ftp-6.0': '{servername} X2 WS_FTP Server 6.0(0)',
    'ws_ftp-6.1': '{servername} X2 WS_FTP Server 6.1(0)',
    'ws_ftp-6.1.1': '{servername} X2 WS_FTP Server 6.1.1(0)',
    'ws_ftp-7.0': '{servername} X2 WS_FTP Server 7.0(0)',
    'ws_ftp-7.1': '{servername} X2 WS_FTP Server 7.1(0)',
    'ws_ftp-7.5': '{servername} X2 WS_FTP Server 7.5(0)',
    'ws_ftp-7.5.1': '{servername} X2 WS_FTP Server 7.5.1(0)',
    'ws_ftp-7.6': '{servername} X2 WS_FTP Server 7.6(0)',
    'ws_ftp-7.6': '{servername} X2 WS_FTP Server 7.6(0) FIPS',
    'ws_ftp-7.6.2': '{servername} X2 WS_FTP Server 7.6.2(0)',
    'ws_ftp-7.6.2-fips': '{servername} X2 WS_FTP Server 7.6.2(0) FIPS',
    'ws_ftp-7.6.3': '{servername} X2 WS_FTP Server 7.6.3(0)',
    'ws_ftp-7.7': '{servername} X2 WS_FTP Server 7.7(0)',
}

class FakeFTPHandler(FTPHandler, object):

    def ftp_PASS(self, line):

        # Dynamically add user to authorizer
        if not self.authorizer.has_user(self.username):
            self.authorizer.add_user(self.username, line, self.ftproot_path, 'elradfmwM')

        return super(FakeFTPHandler, self).ftp_PASS(line)

class TLS_FakeFTPHandler(TLS_FTPHandler, object):

    def ftp_PASS(self, line):

        # Dynamically add user to authorizer
        if not self.authorizer.has_user(self.username):
            self.authorizer.add_user(self.username, line, self.ftproot_path, 'elradfmwM')

        return super(TLS_FakeFTPHandler, self).ftp_PASS(line)

class FakeFS(AbstractedFS):

    def open(self, filename, mode):

        # If virtual filename does not exist return a default file based on extention
        if not self.lexists(filename):

            file_basename, file_extension = os.path.splitext(filename)

            # Calculate absolute path to a fake file
            filename = os.path.join(os.path.dirname(filename), EXT_FILE_RESPONSE.get(file_extension.lower(), u'FakeNetMini.exe'))

        return super(FakeFS, self).open(filename, mode)

    def chdir(self, path):

        # If virtual directory does not exist change to the current directory
        if not self.lexists(path):
            path = u'.'

        return super(FakeFS, self).chdir(path)

    def remove(self, path):

        # Don't remove anything
        pass

    def rmdir(self, path):

        # Don't remove anything
        pass

class FTPListener(object):

    def taste(self, data, dport):

        # See RFC5797 for full command list. Many of these commands are not likely
        # to be used but are included in case malware uses FTP in unexpected ways
        base_ftp_commands = [
            'abor', 'acct', 'allo', 'appe', 'cwd', 'dele', 'help', 'list', 'mode', 
            'nlst', 'noop', 'pass', 'pasv', 'port', 'quit', 'rein', 'rest', 'retr',
            'rnfr', 'rnto', 'site', 'stat', 'stor', 'stru', 'type', 'user'
        ]
        opt_ftp_commands = [
            'cdup', 'mkd', 'pwd', 'rmd', 'smnt', 'stou', 'syst'
        ]

        confidence = 1 if dport == 21 else 0 

        data = data.lstrip().lower()
        for command in base_ftp_commands + opt_ftp_commands:
            if data.startswith(command):
                return confidence + 1

        return confidence

    def __init__(self,
            config,
            name='FTPListener',
            logging_level=logging.INFO,
            running_listeners=None,
            diverter=None
            ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)

        self.config = config
        self.name = name
        self.local_ip = config.get('ipaddr')
        self.server = None
        self.running_listeners = running_listeners
        self.diverter = diverter
        self.name = 'FTP'
        self.port = self.config.get('port', 21)

        self.logger.debug('Starting...')

        self.logger.debug('Initialized with config:')
        for key, value in config.iteritems():
            self.logger.debug('  %10s: %s', key, value)

        # Initialize ftproot directory
        path = self.config.get('ftproot','defaultFiles')
        self.ftproot_path = ListenerBase.abs_config_path(path)
        if self.ftproot_path is None:
            self.logger.error('Could not locate ftproot directory: %s', path)
            sys.exit(1)

    def expand_ports(self, ports_list):
        ports = []
        for i in ports_list.split(','):
            if '-' not in i:
                ports.append(int(i))
            else:
                l,h = map(int, i.split('-'))
                ports+= range(l,h+1)
        return ports

    def start(self):

        self.authorizer = DummyAuthorizer()


        if self.config.get('usessl') == 'Yes':
            self.logger.debug('Using SSL socket.')

            keyfile_path = 'listeners/ssl_utils/privkey.pem'
            keyfile_path = ListenerBase.abs_config_path(keyfile_path)
            if keyfile_path is None:
                self.logger.error('Could not locate %s', keyfile_path)
                sys.exit(1)

            self.handler = TLS_FakeFTPHandler
            self.handler.certfile = keyfile_path

        else:
            self.handler = FakeFTPHandler

        self.handler.banner = self.genBanner()

        self.handler.ftproot_path = self.ftproot_path
        self.handler.abstracted_fs = FakeFS

        self.handler.authorizer = self.authorizer
        self.handler.passive_ports = self.expand_ports(self.config.get('pasvports', '60000-60010'))


        self.server = ThreadedFTPServer((self.local_ip, int(self.config['port'])), self.handler)

        # Override pyftpdlib logger name
        logging.getLogger('pyftpdlib').name = self.name


        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.debug('Stopping...')
        if self.server:
            self.server.close_all()

    def genBanner(self):
        bannerfactory = BannerFactory.BannerFactory()
        return bannerfactory.genBanner(self.config, BANNERS)

###############################################################################
# Testing code
def test(config):

    import ftplib

    client = ftplib.FTP()
    client.connect('localhost', int(config.get('port', 21)))

    client.login('user', 'password')

    client.dir('.')

    client.close()

def main():
    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)

    config = {'port': '21', 'usessl': 'No', 'protocol': 'tcp', 'ftproot': os.path.join('..', 'defaultFiles')}

    listener = FTPListener(config)
    listener.start()


    ###########################################################################
    # Run processing
    import time

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    ###########################################################################
    # Run tests
    test(config)

if __name__ == '__main__':
    main()
