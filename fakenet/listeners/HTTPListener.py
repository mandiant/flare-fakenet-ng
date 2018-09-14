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



def load_cert(certpath):
    try:
        with open(certpath, "rb") as certfile:
            data = certfile.read()
        cacert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
    except:
        traceback.print_exc()
        cacert = None
    return cacert


def load_private_key(keypath):
    try:
        with open(keypath, "rb") as keyfile:
            data = keyfile.read()
        privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, data)
    except:
        traceback.print_exc()
        privkey = None
    return privkey


class HTTPListener(object):
    SSL_UTILS = os.path.join("listeners", "ssl_utils")
    CERT_DIR = os.path.join(SSL_UTILS, "temp_certs")
    CN="fakenet.flare"
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

    def prepare_certs(self):
        if not os.path.isdir(self.CERT_DIR):
            os.makedirs(self.CERT_DIR)

        # Generate and add a root CA, which is used to sign for other certs
        if self.config.get("static_ca") == "Yes":
            # self.ca_cert, self.ca_key = self.CA_CERT, self.CA_KEY
            self.ca_cert = self.config.get("ca_cert", "")
            self.ca_key = self.config.get("ca_key", "")
            msg = "Using the following root CA: %s" % (self.ca_cert,)
            self.logger.info(msg)
            self.add_root_ca(self.CA_CERT)
        else:
            self.logger.info("Generating a new Root CA")
            self.ca_cert, self.ca_key = self.create_cert(self.CN)
            self.add_root_ca(self.ca_cert)

    def start(self):
        self.logger.debug('Starting...')

        self.server = ThreadedHTTPServer((self.local_ip, int(self.config.get('port'))), ThreadedHTTPRequestHandler)
        self.server.logger = self.logger
        self.server.config = self.config
        self.server.webroot_path = self.webroot_path
        self.server.extensions_map = self.extensions_map

        if self.config.get('usessl') == 'Yes':
            self.prepare_certs()
            self.logger.debug('Using SSL socket.')
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            self.logger.error("setting callback to %s" % str(self.sni_callback))
            ctx.set_servername_callback(self.sni_callback)
            ctx.load_cert_chain(certfile=self.ca_cert, keyfile=self.ca_key)
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.info('Stopping...')
        if self.server:
            self.server.shutdown()
            self.server.server_close()

        if self.config.get('usessl' == 'Yes'):
            cert = load_cert(self.ca_cert)
            if cert is not None:
                self.remove_root_ca(cert.get_subject().CN)
            try:
                shutil.rmtree(self.CERT_DIR)
            except:
                pass

    def sni_callback(self, sslsock, servername, sslctx):
        """
        Callback to handle new SSL ClientHello message. The call back MUST
        return None for SSL to continue handling the handshake. Any other
        numerical values are used as error codes.
        """
        newctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        certfile, keyfile = self.create_cert(servername, self.ca_cert, self.ca_key)
        if certfile is None or keyfile is None:
            return None

        newctx.check_hostname = False
        newctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        sslsock.context = newctx
        return None

    def add_root_ca(self, ca_cert_file):
        try:
            subprocess.check_call(
                ["certutil", "-addstore", "Root", ca_cert_file],
                shell=True, stdout=None
            )
            rc = True
        except subprocess.CalledProcessError:
            rc = False
            self.logger.error("Failed to add root CA")
            self.logger.error(traceback.format_exc())
        return rc

    def remove_root_ca(self, cn):
        try:
            subprocess.check_call(
                ["certutil", "-delstore", "Root", cn],
                shell=True
            )
            rc = True
        except subprocess.CalledProcessError:
            rc = False
            self.logger.error("Failed to add root CA")
            self.logger.error(traceback.format_exc())
        return rc

    def create_cert(self, cn, ca_cert=None, ca_key=None, cert_dir=None):
        """
        Create a cert given the common name, a signing CA, CA private key and
        the directory output.

        return: tuple(None, None) on error
                tuple(cert_file_path, key_file_path) on success
        """

        f_selfsign = ca_cert is None or ca_key is None
        certdir = self.CERT_DIR if cert_dir is None else cert_dir

        certfile = os.path.join(certdir, "%s.crt" % (cn))
        keyfile = os.path.join(certdir, "%s.key" % (cn))
        if os.path.exists(certfile):
            return certfile, keyfile

        f_selfsign = True
        if ca_cert is not None and ca_key is not None:
            f_selfsign = False
            cacert = load_cert(ca_cert)
            if cacert is None:
                return None, None

            cakey = load_private_key(ca_key)
            if cakey is None:
                return None, None

        # generate crypto keys:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Create a cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().CN = cn
        cert.set_serial_number(0x31337)
        now = time.time() / 1000000
        na = int(now + self.NOT_AFTER_DELTA_SECONDS)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(na)
        cert.set_pubkey(key)
        if f_selfsign:
            cert.set_issuer(cert.get_subject())
            cert.sign(key, "sha1")
        else:
            cert.set_issuer(cacert.get_subject())
            cert.sign(cakey, "sha1")

        try:
            with open(certfile, "wb") as cert_file:
                cert_file.write(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, cert)
                )
            with open(keyfile, "wb") as key_file:
                key_file.write(crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, key)
                )
        except:
            traceback.print_exc()
            return None, None
        return certfile, keyfile

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
        response, response_type = self.get_response(self.path)

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

        self.server.logger.info('Responding with mime type: %s file: %s', response_type, response_filename)

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
