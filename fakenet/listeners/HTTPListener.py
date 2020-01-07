import logging
from ConfigParser import ConfigParser

import os
import sys
import imp

import threading
import SocketServer
import BaseHTTPServer

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

INDENT = '  '


def qualify_file_path(filename, fallbackdir):
    path = filename
    if path:
        if not os.path.exists(path):
            path = os.path.join(fallbackdir, filename)
        if not os.path.exists(path):
            raise RuntimeError('Cannot find %s' % (filename))

    return path


class CustomResponse(object):
    def __init__(self, name, conf, configroot):
        self.name = name

        match_specs = {'httpuris', 'httphosts'}
        response_specs = {'httprawfile', 'httpstaticstring', 'httpdynamic'}

        if not match_specs.intersection(conf):
            raise ValueError('Custom HTTP config section %s lacks '
                             '%s' % (name, '/'.join(match_specs)))

        nr_responses = len(response_specs.intersection(conf))
        if nr_responses != 1:
            raise ValueError('Custom HTTP config section %s has %d of %s' %
                             (name, nr_responses, '/'.join(response_specs)))

        if ('contenttype' in conf) and ('httpstaticstring' not in conf):
            raise ValueError('Custom HTTP config section %s has ContentType '
                             'which is only usable with '
                             'HttpStaticString' % (name))

        self.uris = conf.get('httpuris', {})
        if self.uris:
            self.uris = {u.strip() for u in self.uris.split(',')}

        self.hosts = conf.get('httphosts', {})
        if self.hosts:
            self.hosts = {h.strip().lower() for h in self.hosts.split(',')}

        self.raw_file = qualify_file_path(conf.get('httprawfile'), configroot)
        if self.raw_file:
            self.raw_file = open(self.raw_file, 'rb').read()

        self.handler = None
        pymod_path = qualify_file_path(conf.get('httpdynamic'), configroot)
        if pymod_path:
            pymod = imp.load_source('cr_' + self.name, pymod_path)
            funcname = 'HandleHttp'
            funcname_legacy = 'HandleRequest'
            if hasattr(pymod, funcname):
                self.handler = getattr(pymod, funcname)
            elif hasattr(pymod, funcname_legacy):
                self.handler = getattr(pymod, funcname_legacy)
            else:
                raise ValueError('Loaded %s module %s has no function %s' %
                                 ('httpdynamic', conf.get('httpdynamic'),
                                  funcname))

        self.static_string = conf.get('httpstaticstring')
        if self.static_string is not None:
            self.static_string = self.static_string.replace('\\r\\n', '\r\n')
        self.content_type = conf.get('ContentType')

    def checkMatch(self, host, uri):
        hostmatch = (host.strip().lower() in self.hosts)
        if (not hostmatch) and (':' in host):
            host = host[:host.find(':')]
            hostmatch = (host.strip().lower() in self.hosts)


        urimatch = False
        for match_uri in self.uris:
            if uri.endswith(match_uri):
                urimatch = True
                break

        # Conjunctive (logical and) evaluation if both are specified
        if self.uris and self.hosts:
            return hostmatch and urimatch
        else:
            return hostmatch or urimatch

    def respond(self, req, meth, postdata=None):
        current_time = req.date_time_string()
        if self.raw_file:
            up_to_date = self.raw_file.replace('<RAW-DATE>', current_time)
            req.wfile.write(up_to_date)
        elif self.handler:
            self.handler(req, meth, postdata)
        elif self.static_string is not None:
            up_to_date = self.static_string.replace('<RAW-DATE>', current_time)
            req.send_response(200)
            req.send_header('Content-Length', len(up_to_date))
            if self.content_type:
                req.send_header('Content-Type', self.content_type)
            req.end_headers()
            req.wfile.write(up_to_date)


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
        self.local_ip = config.get('ipaddr')
        self.server = None
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
        self.server = ThreadedHTTPServer((self.local_ip, int(self.config.get('port'))), ThreadedHTTPRequestHandler)
        self.server.logger = self.logger
        self.server.config = self.config
        self.server.webroot_path = self.webroot_path
        self.server.extensions_map = self.extensions_map

        if self.config.get('usessl') == 'Yes':
            self.logger.debug('Using SSL socket.')

            keyfile_path = 'listeners/ssl_utils/privkey.pem'
            keyfile_path = ListenerBase.abs_config_path(keyfile_path)
            if keyfile_path is None:
                raise RuntimeError('Could not locate %s' % (keyfile_path))

            certfile_path = 'listeners/ssl_utils/server.pem'
            certfile_path = ListenerBase.abs_config_path(certfile_path)
            if certfile_path is None:
                raise RuntimeError('Could not locate %s' % (certfile_path))

            self.server.socket = ssl.wrap_socket(self.server.socket, keyfile=keyfile_path, certfile=certfile_path, server_side=True, ciphers='RSA')

        self.server.custom_responses = []
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
                        checkSetting(entries, 'listenertype', 'HTTP')):
                    cr = CustomResponse(section, entries, configdir)
                    self.server.custom_responses.append(cr)

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
        self.logger = self.server.logger

    def version_string(self):
        return self.server.config.get('version', "FakeNet/1.3")

    def setup(self):
        self.request.settimeout(int(self.server.config.get('timeout', 5)))
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

    def doCustomResponse(self, meth, post_data=None):
        uri = self.path
        host = self.headers.get('host', '')

        for cr in self.server.custom_responses:
            if cr.checkMatch(host, uri):
                self.server.logger.debug('Invoking custom response %s' % (cr.name))
                cr.respond(self, meth, post_data)
                return True

        return False

    def do_HEAD(self):
        # Log request
        self.server.logger.info(INDENT + self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(INDENT + line)

        # Prepare response
        if not self.doCustomResponse('HEAD'):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

    def do_GET(self):
        # Log request
        self.server.logger.info(INDENT + self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(INDENT + line)

        # Prepare response
        if not self.doCustomResponse('GET'):
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

        # Log request
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

        # Prepare response
        if not self.doCustomResponse('GET', post_body):
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
