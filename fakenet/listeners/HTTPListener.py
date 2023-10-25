import logging

import os
import sys

import threading
import SocketServer
import BaseHTTPServer

import ssl
import socket

import posixpath
import mimetypes

import time
import shutil
import traceback
import subprocess
from OpenSSL import crypto
from ssl_utils import SSLWrapper
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

INDENT = '  '


class HTTPListener(object):
    SSL_UTILS = os.path.join("listeners", "ssl_utils")
    CA_CERT = os.path.join(SSL_UTILS, "server.pem")
    CA_KEY = os.path.join(SSL_UTILS, "privkey.pem")
    NOT_AFTER_DELTA_SECONDS = 300  * 24 * 60 * 60

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
        self.local_ip = config.get('ipaddr')
        self.server = None
        self.name = 'HTTP'
        self.port = self.config.get('port', 80)
        self.sslwrapper = None

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

        self.server = ThreadedHTTPServer((self.local_ip,
            int(self.config.get('port'))), ThreadedHTTPRequestHandler)
        self.server.logger = self.logger
        self.server.config = self.config
        self.server.webroot_path = self.webroot_path
        self.server.extensions_map = self.extensions_map

        if self.config.get('usessl') == 'Yes':
            self.logger.debug("HTTP Listener starting with SSL")
            config = {
                'cert_dir': self.config.get('cert_dir', 'temp_certs'),
                'networkmode': self.config.get('networkmode', None),
                'static_ca': self.config.get('static_ca', False),
                'ca_cert': self.config.get('ca_cert'),
                'ca_key': self.config.get('ca_key')
            }
            self.sslwrapper = SSLWrapper(config)
            self.server.sslwrapper = self.sslwrapper
            self.server.socket = self.server.sslwrapper.wrap_socket(
                self.server.socket)


        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.debug('Stopping...')
        if self.server:
            self.server.shutdown()
            self.server.server_close()


class ThreadedHTTPServer(BaseHTTPServer.HTTPServer):

    def handle_error(self, request, client_address):
        exctype, value = sys.exc_info()[:2]
        self.logger.error('Error: %s', value)

class ThreadedHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def __init__(self, *args):
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, *args)

    def version_string(self):
	return self.server.config.get('version', "FakeNet/1.3")

    def setup(self):
        self.request.settimeout(int(self.server.config.get('timeout', 5)))
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

    def do_HEAD(self):
        # Process request
        self.server.logger.info(INDENT + self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(INDENT + line)

        # Prepare response
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        # Process request
        self.server.logger.info(INDENT + self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(INDENT + line)

        # Get response type based on the requested path
        response, response_type = self.get_response(self.path)

        # Prepare response
        self.send_response(200)
        self.send_header("Content-Type", response_type)
        self.send_header("Content-Length", len(response))
        self.end_headers()

        self.wfile.write(response)

    def do_POST(self):
        post_body = ''

        content_len = int(self.headers.get('content-length', 0))
        post_body = self.rfile.read(content_len)

        # Process request
        self.server.logger.info(INDENT + self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(INDENT + line)
        for line in post_body.split("\n"):
            self.server.logger.info(INDENT + line)

        # Store HTTP Posts
        if self.server.config.get('dumphttpposts') and self.server.config['dumphttpposts'].lower() == 'yes':
                http_filename = "%s_%s.txt" % (self.server.config.get('dumphttppostsfileprefix', 'http'), time.strftime("%Y%m%d_%H%M%S"))

                self.server.logger.info('Storing HTTP POST headers and data to %s.', http_filename)
                http_f = open(http_filename, 'wb')

                if http_f:
                    http_f.write(self.requestline + "\r\n")
                    http_f.write(str(self.headers) + "\r\n")
                    http_f.write(post_body)

                    http_f.close()
                else:
                    self.server.logger.error('Failed to write HTTP POST headers and data to %s.', http_filename)

        # Get response type based on the requested path
        response, response_type = self.get_response(self.path)

        # Prepare response
        self.send_response(200)
        self.send_header("Content-Type", response_type)
        self.send_header("Content-Length", len(response))
        self.end_headers()

        self.wfile.write(response)

    def get_response(self, path):
        response = "<html><head><title>FakeNet</title><body><h1>FakeNet</h1></body></html>"
        response_type = 'text/html'

        if path[-1] == '/':
            response_type = 'text/html'
            path += 'index.html'
        else:
            _, ext = posixpath.splitext(path)
            response_type = self.server.extensions_map.get(ext, 'text/html')

        # Do after checking for trailing '/' since normpath removes it
        response_filename = ListenerBase.safe_join(self.server.webroot_path, path)

        # Check the requested path exists
        if not os.path.exists(response_filename):

            self.server.logger.debug('Could not find path: %s', response_filename)

            # Try default MIME file
            response_filename = os.path.join(self.server.webroot_path, MIME_FILE_RESPONSE.get(response_type, 'FakeNet.html'))

            # Check default MIME file exists
            if not os.path.exists(response_filename):
                self.server.logger.debug('Could not find path: %s', response_filename)
                self.server.logger.error('Could not locate requested file or default handler.')
                return (response, response_type)

        self.server.logger.debug('Responding with mime type: %s file: %s',
                                 response_type, response_filename)

        try:
            f = open(response_filename, 'rb')
        except Exception, e:
            self.server.logger.error('Failed to open response file: %s', response_filename)
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

    url = "%s://localhost:%s" % ('http' if config.get('usessl') == 'No' else 'https', int(config.get('port', 8080)))

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
    print requests.post(url, {'param1':'A'*80, 'param2':'B'*80}, verify=False, stream=True).text
    print '-'*80

def main():
    """
    Run from the flare-fakenet-ng root dir with the following command:

       python2 -m fakenet.listeners.HTTPListener

    """
    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)

    config = {'port': '8443', 'usessl': 'Yes', 'webroot': 'fakenet/defaultFiles' }

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
