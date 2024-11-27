# Copyright (C) 2016-2023 Mandiant, Inc. All rights reserved.

import logging
from configparser import ConfigParser

import os
import sys
import importlib
import base64

import threading
import socketserver

import ssl
import socket

from . import *

INDENT = '  '


def qualify_file_path(filename, fallbackdir):
    path = filename
    if path:
        if not os.path.exists(path):
            path = os.path.join(fallbackdir, filename)
        if not os.path.exists(path):
            raise RuntimeError('Cannot find %s' % (filename))

    return path


class RawCustomResponse(object):
    def __init__(self, proto, name, conf, configroot):
        self.name = name
        self.static = None
        self.handler = None

        spec_file = '%srawfile' % (proto.lower())
        spec_str = '%sstaticstring' % (proto.lower())
        spec_b64 = '%sstaticbase64' % (proto.lower())
        spec_dyn = '%sdynamic' % (proto.lower())

        response_specs = {
            spec_file,
            spec_str,
            spec_b64,
            spec_dyn,
        }

        nr_responses = len(response_specs.intersection(conf))
        if nr_responses != 1:
            raise ValueError('Custom %s config section %s has %d of %s' %
                             (proto.upper(), name, nr_responses,
                              '/'.join(response_specs)))

        self.static = conf.get(spec_str)

        if self.static is not None:
            self.static = self.static.rstrip('\r\n').encode("utf-8")

        if not self.static is not None:
            b64_text = conf.get(spec_b64)
            if b64_text:
                self.static = base64.b64decode(b64_text)

        if not self.static is not None:
            file_path = conf.get(spec_file)
            if file_path:
                raw_file = qualify_file_path(file_path, configroot)
                self.static = open(raw_file, 'rb').read()

        pymodpath = qualify_file_path(conf.get(spec_dyn), configroot)
        if pymodpath:
            pymod = imp.load_source('cr_raw_' + self.name, pymodpath)
            funcname = 'Handle%s' % (proto.capitalize())
            if not hasattr(pymod, funcname):
                raise ValueError('Loaded %s module %s has no function %s' %
                                 (spec_dyn, conf.get(spec_dyn), funcname))
            self.handler = getattr(pymod, funcname)

    def respondUdp(self, sock, data, addr):
        if self.static:
            sock.sendto(self.static, addr)
        elif self.handler:
            self.handler(sock, data, addr)


class RawListener(object):

    def taste(self, data, dport):
        return 1

    def __init__(self, 
            config, 
            name='RawListener', 
            logging_level=logging.INFO, 
            ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)
            
        self.config = config
        self.name = name
        self.local_ip = config.get('ipaddr')
        self.server = None
        self.port = self.config.get('port', 1337)

        self.logger.debug('Starting...')

        self.logger.debug('Initialized with config:')
        for key, value in config.items():
            self.logger.debug('  %10s: %s', key, value)

    def start(self):

        # Start listener
        proto = self.config.get('protocol')
        if proto is not None:
            if proto.lower() == 'tcp':
                self.logger.debug('Starting TCP ...')
                self.server = ThreadedTCPServer((self.local_ip, int(self.config['port'])), ThreadedTCPRequestHandler)

            elif proto.lower() == 'udp':
                self.logger.debug('Starting UDP ...')
                self.server = ThreadedUDPServer((self.local_ip, int(self.config['port'])), ThreadedUDPRequestHandler)

            else:
                self.logger.error('Unknown protocol %s', self.config['protocol'])
                return
        else:
            self.logger.error('Protocol is not defined.')
            return

        self.server.logger = self.logger
        self.server.config = self.config

        if self.config.get('usessl') == 'Yes':
            self.logger.debug('Using SSL socket.')

            keyfile_path = 'listeners/ssl_utils/privkey.pem'
            keyfile_path = ListenerBase.abs_config_path(keyfile_path)
            if keyfile_path is None:
                self.logger.error('Could not locate %s', keyfile_path)
                sys.exit(1)

            certfile_path = 'listeners/ssl_utils/server.pem'
            certfile_path = ListenerBase.abs_config_path(certfile_path)
            if certfile_path is None:
                self.logger.error('Could not locate %s', certfile_path)
                sys.exit(1)

            self.server.socket = ssl.wrap_socket(self.server.socket, keyfile=keyfile_path, certfile=certfile_path, server_side=True, ciphers='RSA')

        self.server.custom_response = None
        custom = self.config.get('custom')

        def checkSetting(d, name, value):
            if name not in d:
                return False
            return d[name].lower() == value.lower()

        if custom:
            configdir = self.config.get('configdir')
            custom = qualify_file_path(custom, configdir)
            customconf = ConfigParser()
            customconf.read(custom)

            for section in customconf.sections():
                entries = dict(customconf.items(section))

                if (('instancename' not in entries) and
                        ('listenertype' not in entries)):
                    msg = 'Custom Response lacks ListenerType or InstanceName'
                    raise RuntimeError(msg)

                if (checkSetting(entries, 'instancename', self.name) or
                        checkSetting(entries, 'listenertype', proto)):

                    if self.server.custom_response:
                        msg = ('Only one %s Custom Response can be configured '
                               'at a time' % (proto))
                        raise RuntimeError(msg)

                    self.server.custom_response = (
                        RawCustomResponse(proto, section, entries, configdir))

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.debug('Stopping...')
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def acceptDiverterListenerCallbacks(self, diverterListenerCallbacks):
        self.server.diverterListenerCallbacks = diverterListenerCallbacks

class SocketWithHexdumpRecv():
    def __init__(self, s, logger):
        self.s = s
        self.logger = logger

    def __getattr__(self, item):
        if 'recv' == item:
            return self.recv
        else:
            return getattr(self.s, item)

    def do_hexdump(self, data):
        hexdump_lines = hexdump_table(data)

        for line in hexdump_lines:
            self.logger.info(INDENT + line)

    # Hook to ensure that all `recv` calls transparently emit a hex dump
    # in the log output, even if they occur within a user-implemented
    # custom handler
    def recv(self, n, flags=0):
        data = self.s.recv(n, flags)
        if data:
            self.do_hexdump(data)
        return data

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        # Using a custom class, SocketWithHexdumpRecv, so as to hook the recv function
        # setattr(self.request, 'recv', hook_recv) stopped working in python 3
        # as recv attribute became read-only

        self.request = SocketWithHexdumpRecv(self.request, self.server.logger)

        # Timeout connection to prevent hanging
        self.request.settimeout(int(self.server.config.get('timeout', 5)))

        cr = self.server.custom_response

        # Allow user-scripted responses to handle all control flow (e.g.
        # looping, exception handling, etc.)
        if cr and cr.handler:
            cr.handler(self.request)
        else:
            try:
                    
                while True:
                    data = self.request.recv(1024)
                    if not data:
                        break

                    # Collect NBIs
                    hexdump_lines = hexdump_table(data)
                    collect_nbi(self.client_address[1], hexdump_lines,
                                self.server.config.get('protocol'),
                                self.server.config.get('usessl'),
                                self.server.diverterListenerCallbacks)

                    if cr and cr.static:
                        self.request.sendall(cr.static)
                    else:
                        self.request.sendall(data)

            except socket.timeout:
                self.server.logger.warning('Connection timeout')

            except socket.error as msg:
                self.server.logger.error('Error: %s', msg.strerror or msg)

            except Exception as e:
                self.server.logger.error('Error: %s', e)

class ThreadedUDPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        (data,sock) = self.request

        if data:
            # Collect NBIs
            hexdump_lines = hexdump_table(data)
            collect_nbi(self.client_address[1], hexdump_lines,
                        self.server.config.get('protocol'),
                        self.server.config.get('usessl'),
                        self.server.diverterListenerCallbacks)

            for line in hexdump_lines:
                self.server.logger.info(INDENT + line)

        cr = self.server.custom_response
        if cr:
            cr.respondUdp(sock, data, self.client_address)
        elif data:
            try:
                sock.sendto(data, self.client_address)

            except socket.error as msg:
                self.server.logger.error('Error: %s', msg.strerror or msg)

            except Exception as e:
                self.server.logger.error('Error: %s', e)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # Avoid [Errno 98] Address already in use due to TIME_WAIT status on TCP
    # sockets, for details see:
    # https://stackoverflow.com/questions/4465959/python-errno-98-address-already-in-use
    allow_reuse_address = True

class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    pass

def hexdump_table(data, length=16):

    hexdump_lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_line   = ' '.join(["%02X" % b for b in chunk ] )
        ascii_line = ''.join([chr(b) if b > 31 and b < 127 else '.' for b in chunk ] )
        hexdump_lines.append("%04X: %-*s %s" % (i, length*3, hex_line, ascii_line ))
    return hexdump_lines

def collect_nbi(sport, hexdump_lines, proto, is_ssl_encrypted,
        diverterCallbacks):
    nbi = {}
    # Show upto 16 lines of hex dump
    nbi['Data Hexdump'] = hexdump_lines[:16]

    # Report diverter everytime we capture an NBI
    # Using an empty string for application_layer_protocol in Raw Listener so
    # that diverter can override the empty string with the
    # transport_layer_protocol
    diverterCallbacks.logNbi(sport, nbi, proto, '', is_ssl_encrypted)

###############################################################################
# Testing code
def test(config):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("\t[RawListener] Sending request:\n%s" % "HELO\n")
    try:
        # Connect to server and send data
        sock.connect(('localhost', int(config.get('port', 23))))
        sock.sendall(b"HELO\n")

        # Receive data from the server and shut down
        received = sock.recv(1024)
    finally:
        sock.close()

def main():
    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)

    config = {'port': '1337', 'usessl': 'No', 'protocol': 'tcp'}

    listener = RawListener(config)
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
    #test(config)

    listener.stop()

if __name__ == '__main__':
    main()
