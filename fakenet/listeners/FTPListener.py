import logging

import os
import sys

import threading
import SocketServer

import ssl
import socket

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.filesystems import AbstractedFS
from pyftpdlib.servers import ThreadedFTPServer

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

class FTPListener():

    def __init__(self, config, name = 'FTPListener', logging_level = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)
            
        self.config = config
        self.name = name
        self.local_ip = '0.0.0.0'
        self.server = None

        self.logger.info('Starting...')

        self.logger.debug('Initialized with config:')
        for key, value in config.iteritems():
            self.logger.debug('  %10s: %s', key, value)

        # Initialize webroot directory
        self.ftproot_path = self.config.get('ftproot','defaultFiles')

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

            keyfile_path = 'privkey.pem'
            self.handler = TLS_FakeFTPHandler
            self.handler.certfile = keyfile_path

        else:
            self.handler = FakeFTPHandler



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

    config = {'port': '21', 'usessl': 'No', 'protocol': 'tcp', 'ftproot': '..\defaultFiles'}

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