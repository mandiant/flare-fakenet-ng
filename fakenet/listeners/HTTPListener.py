import logging

import os
import sys
import imp

import threading
import SocketServer
import BaseHTTPServer
from collections import namedtuple

import ssl
import socket

import posixpath
import mimetypes

import time

from . import *


MIME_FILE_RESPONSE = {
    'text/html':    'FakeNet.html',
    'image/png':    'FakeNet.png',
    'image/ico':    'FakeNet.ico',
    'image/jpeg':   'FakeNet.jpg',
    'application/octet-stream': 'FakeNetMini.exe',
    'application/x-msdownload': 'FakeNetMini.exe',
    'application/x-msdos-program': 'FakeNetMini.exe',
    'application/pdf': 'FakeNet.pdf',
    'application/xml': 'FakeNet.html'
}

class HTTPListener(object):

    def taste(self, data, dport):

        request_methods = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE',
            'OPTIONS', 'CONNECT', 'PATCH']

        confidence = 1 if dport in [80, 443] else 0

        for method in request_methods:
            if data.lstrip().startswith(method):
                confidence += 2
                continue

        return confidence

    if not mimetypes.inited:
        mimetypes.init() # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'text/html', # Default
        })

    def __init__(
            self,
            config={},
            name='HTTPListener',
            logging_level=logging.DEBUG,
            ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)

        self.config = config
        self.name = name
        self.local_ip  = '0.0.0.0'
        self.server = None
        self.name = 'HTTP'
        self.port = self.config.get('port', 80)

        self.logger.debug('Initialized with config:')
        for key, value in config.iteritems():
            self.logger.debug('  %10s: %s', key, value)

        # Initialize webroot directory
        path = self.config.get('webroot','defaultFiles')
        self.webroot_path = ListenerBase.abs_config_path(path)
        if self.webroot_path is None:
            self.logger.error('Could not locate webroot directory: %s', path)
            sys.exit(1)


    def start(self):
        self.logger.debug('Starting...')

        def handler(*args):
            return ThreadedHTTPRequestHandler(self.config, *args)
        self.server = ThreadedHTTPServer(
            (self.local_ip, int(self.config.get('port'))),
            handler)
        self.server.logger = self.logger
        self.server.config = self.config
        self.server.webroot_path = self.webroot_path
        self.server.extensions_map = self.extensions_map

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

            self.server.socket = ssl.wrap_socket(
                self.server.socket,
                keyfile=keyfile_path,
                certfile=certfile_path,
                server_side=True, ciphers='RSA')

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.info('Stopping...')
        if self.server:
            self.server.shutdown()
            self.server.server_close()


class ThreadedHTTPServer(BaseHTTPServer.HTTPServer):

    def handle_error(self, request, client_address):
        exctype, value = sys.exc_info()[:2]
        self.logger.error('Error: %s', value)

class ThreadedHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def __init__(self, config, *args):
        self.handler_map = self.initialize_handler_map(config)
        for c2 in self.handler_map:
            handler, data = self.handler_map[c2]
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, *args)

    def initialize_handler_map(self, config):
        C2Handler = namedtuple('C2Handler', 'handle data')
        _map = dict()

        # process static file handler
        c2list, data = [], None
        try:
            c2s = config.get('staticfile_c2', '').split(',')
            data = config.get('staticfile_path', '')
            if data:
                c2list = [c2.strip() for c2 in c2s if c2]
        except:
            c2list, data = [], None
        for c2 in c2list:
            _map[c2] = C2Handler(self.handle_static_file, data)
        
        # process static data handler
        c2list, data = [], None
        try:
            c2s = config.get('static_c2', '').split(',')
            data = config.get('static_data', '')
            if data:
                c2list = [c2.strip() for c2 in c2s if c2]
        except:
            c2list, data = [], None
        for c2 in c2list:
            _map[c2] = C2Handler(self.handle_static, data)
        
        # process custom handler
        c2list, data = [], None
        try:
            c2s = config.get('custom_c2', '').split(',')
            data = config.get('custom_provider', '')
            if data:
                c2list = [c2.strip() for c2 in c2s if c2]
        except:
            c2list, data = [], None
        for c2 in c2list:
            _map[c2] = C2Handler(self.handle_custom, data)
        
        return _map

    def initialize_custom_config(self, config, c2key, datakey):

        c2list, data = [], None
        try:
            c2s = config.get(c2key, '').split(',')
            data = config.get(datakey, '')
            if data:
                c2list = [c2.strip() for c2 in c2s if c2]
        except:
            c2list, data = [], None
        return c2list, data

    def version_string(self):
        return self.server.config.get('version', "FakeNet/1.3")

    def setup(self):
        self.request.settimeout(int(self.server.config.get('timeout', 5)))
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

    def do_HEAD(self):
        self.server.logger.info('Received HEAD request')

        # Process request
        self.server.logger.info('%s', '-'*80)
        self.server.logger.info(self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(line)
        self.server.logger.info('%s', '-'*80)

        # Prepare response
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):

        self.server.logger.info('Received a GET request.')

        # Process request
        self.server.logger.info('%s', '-'*80)
        self.server.logger.info(self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(line)
        self.server.logger.info('%s', '-'*80)

        # Get response type based on the requested path
        response, response_type = self.get_response('GET', self.path)

        # Prepare response
        self.send_response(200)
        self.send_header("Content-Type", response_type)
        self.send_header("Content-Length", len(response))
        self.end_headers()

        self.wfile.write(response)

    def do_POST(self):
        self.server.logger.info('Received a POST request')

        post_body = ''

        content_len = int(self.headers.get('content-length', 0))
        post_body = self.rfile.read(content_len)

        # Process request
        self.server.logger.info('%s', '-'*80)
        self.server.logger.info(self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(line)
        for line in post_body.split("\n"):
            self.server.logger.info(line)
        self.server.logger.info('%s', '-'*80)

        # Store HTTP Posts
        if self.server.config.get('dumphttpposts') and \
           self.server.config['dumphttpposts'].lower() == 'yes':
            http_filename = "%s_%s.txt" % (
                self.server.config.get('dumphttppostsfileprefix', 'http'),
                time.strftime("%Y%m%d_%H%M%S"))

            self.server.logger.info(
                'Storing HTTP POST headers and data to %s.', http_filename)
            http_f = open(http_filename, 'wb')

            if http_f:
                http_f.write(self.requestline + "\r\n")
                http_f.write(str(self.headers) + "\r\n")
                http_f.write(post_body)

                http_f.close()
            else:
                self.server.logger.error(
                    'Failed to write HTTP POST headers and data to %s.', 
                    ttp_filename)

        # Get response type based on the requested path
        response, response_type = self.get_response(
            'POST', self.path, post_body)

        # Prepare response
        self.send_response(200)
        self.send_header("Content-Type", response_type)
        self.send_header("Content-Length", len(response))
        self.end_headers()

        self.wfile.write(response)

    def get_response(self, method, path, post_data=None):
        hostname = self.headers.get('Host', '')
        handler = self.handler_map.get(hostname, None)
        if handler is None:
            return self.get_default_response(self.path, method)
        print handler.handle, handler.data
        return handler.handle(method, handler.data, post_data=post_data)

    def handle_custom(self, method, provider, post_data=None):
        mod_path = os.path.join(self.server.webroot_path, 'providers')
        provider_path = os.path.join(mod_path, provider)
        try:
            mod = imp.load_source('mod', provider_path)
        except:
            response, content_type = self.get_default_response(
                self.path, method, post_data)
        else:
            response, content_type = mod.HandleRequest(self, method, post_data)
        return response, content_type

    def handle_static_file(self, method, static_file_path, post_data=None):
        static_dir = os.path.abspath(os.path.join(
            self.server.webroot_path,
            # self.headers.get('Host', '.'),    # NOTE: Should we support this?
            static_file_path))
        if self.path[0] == '/':
            request_path = self.path[1:]
        else:
            request_path = self.path
        filepath = os.path.join(static_dir, request_path)
        try:
            with open(filepath, 'rb') as fd:
                data = fd.read()
        except IOError as _ioe:
            response, content_type = self.get_default_response(
                self.path, method, post_data)
        else:
            response, content_type = data, "text/html"
        return response, content_type

    def handle_static(self, method, data, post_data=None):
        return data, "text/html"

    def get_default_response(self, path, method, post_data=None):
        response = "<html>"
        response += "<head><title>FakeNet</title></head>"
        response += "<body><h1>FakeNet</h1></body>"
        response += "</html>"
        response_type = 'text/html'
        
        if path[-1] == '/':
            response_type = 'text/html'
            path += 'index.html'
        else:
            _, ext = posixpath.splitext(path)
            response_type = self.server.extensions_map.get(ext, 'text/html')

        # Do after checking for trailing '/' since normpath removes it
        response_filename = ListenerBase.safe_join(self.server.webroot_path,
            path)

        # Check the requested path exists
        if not os.path.exists(response_filename):

            self.server.logger.debug('Could not find path: %s',
                response_filename)

            # Try default MIME file
            response_filename = os.path.join(
                self.server.webroot_path,
                MIME_FILE_RESPONSE.get(response_type, 'FakeNet.html'))

            # Check default MIME file exists
            if not os.path.exists(response_filename):
                self.server.logger.debug(
                    'Could not find path: %s', response_filename)
                self.server.logger.error(
                    'Could not locate requested file or default handler.')
                return (response, response_type)

        self.server.logger.info(
            'Responding with mime type: %s file: %s',
            response_type, response_filename)

        try:
            f = open(response_filename, 'rb')
        except Exception, e:
            self.server.logger.error(
                'Failed to open response file: %s', response_filename)
            response_type = 'text/html'
        else:
            response = f.read()
            f.close()

        return (response, response_type)

    def log_message(self, format, *args):
        return


###############################################################################
# Testing code
def test(config):

    import requests

    url = "%s://localhost:%s" % (
        'http' if config.get('usessl') == 'No' else 'https',
        int(config.get('port', 8080)))

    print "\t[HTTPListener] Testing HEAD request."
    print '-'*80
    print requests.head(url, verify=False, stream=True).text
    print '-'*80

    print "\t[HTTPListener] Testing GET request."
    print '-'*80
    print requests.get(url, verify=False, stream=True).text
    print '-'*80

    print "\t[HTTPListener] Testing POST request."
    print '-'*80
    print requests.post(url, 
        {'param1':'A'*80, 'param2':'B'*80},
        verify=False, stream=True).text
    print '-'*80

def main():
    """
    Run from the flare-fakenet-ng root dir with the following command:

       python2 -m fakenet.listeners.HTTPListener

    """
    logging.basicConfig(
        format='%(asctime)s [%(name)15s] %(message)s',
        datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)

    config = {
        'port': '8443',
        'usessl': 'Yes',
        'webroot': 'fakenet/defaultFiles' }

    listener = HTTPListener(config)
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
