import time
import os
import traceback
import subprocess
import logging
import shutil
import sys
import ssl
import random
from listeners import ListenerBase
from OpenSSL import crypto

g_ssl_fellback = False  # Notify only once of SSL static certificate fallback


class SSLWrapper(object):
    NOT_AFTER_DELTA_SECONDS = 300  * 24 * 60 * 60
    CN="fakenet.flare"

    def __init__(self, config):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = config
        self.ca_cert = None
        self.ca_key = None

        cert_dir = self.config.get('cert_dir', None)
        if cert_dir is None:
            raise RuntimeError("certdir key is not specified in config")

        if not os.path.isdir(cert_dir):
            os.makedirs(cert_dir)

        # generate and add root CA, which is used to sign for other certs:
        if self.config.get('static_ca') == 'Yes':
            self.ca_cert = self.config.get('ca_cert', None)
            self.ca_key = self.config.get('ca_key', None)
        else:
            self.ca_cert, self.ca_key = self.create_cert(self.CN)
        if ( not self.config.get('networkmode', None) == 'multihost' and 
             not self.config.get('static_ca') == 'Yes'): 
            self.logger.debug('adding root cert: %s', self.ca_cert)
            self._add_root_ca(self.ca_cert)

    def wrap_socket(self, s):
        global g_ssl_fellback
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        except AttributeError as e:
            if not g_ssl_fellback:
                g_ssl_fellback = True
                self.logger.error('Exception calling ssl.SSLContext: %s' %
                                  (e.message))
                self.logger.error('Falling back on static certificate')
            return self.wrap_socket_fallback(s)
        else:
            ctx.set_servername_callback(self.sni_callback)
            ctx.load_cert_chain(certfile=self.ca_cert, keyfile=self.ca_key)
            return ctx.wrap_socket(s, server_side=True)

    def wrap_socket_fallback(self, s):
        keyfile_path = 'listeners/ssl_utils/privkey.pem'
        keyfile_path = ListenerBase.abs_config_path(keyfile_path)
        if keyfile_path is None:
            raise RuntimeError('Could not locate %s', (key_file,))

        certfile_path = 'listeners/ssl_utils/server.pem'
        certfile_path = ListenerBase.abs_config_path(certfile_path)
        if certfile_path is None:
            raise RuntimeError('Cound not locate %s' % (certfile_path,))
        
        return ssl.wrap_socket(s, keyfile=keyfile_path, certfile=certfile_path,
                               server_side=True, ciphers='RSA')


    def create_cert(self, cn, ca_cert=None, ca_key=None, cert_dir=None):
        """
        Create a cert given the common name, a signing CA, CA private key and
        the directory output.

        return: tuple(None, None) on error
                tuple(cert_file_path, key_file_path) on success
        """

        f_selfsign = ca_cert is None or ca_key is None
        if not cert_dir:
            cert_dir = os.path.abspath(self.config.get('cert_dir'))
        else:
            cert_dir = os.path.abspath(cert_dir)
        
        cert_file = os.path.join(cert_dir, "%s.crt" % (cn))
        key_file = os.path.join(cert_dir, "%s.key" % (cn))
        if os.path.exists(cert_file) and os.path.exists(key_file):
            return cert_file, key_file

        if ca_cert is not None and ca_key is not None:
            ca_cert_data = self._load_cert(ca_cert)
            if ca_cert_data is None:
                return None, None

            ca_key_data = self._load_private_key(ca_key)
            if ca_key_data is None:
                return None, None

        # generate crypto keys:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Create a cert

        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().CN = cn
        cert.set_serial_number(random.randint(1, 0x31337))
        now = time.time() / 1000000
        na = int(now + self.NOT_AFTER_DELTA_SECONDS)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(na)
        cert.set_pubkey(key)
        if f_selfsign:
            cert.set_issuer(cert.get_subject())
            cert.sign(key, "sha1")
        else:
            cert.set_issuer(ca_cert_data.get_subject())
            cert.sign(ca_key_data, "sha1")

        try:
            with open(cert_file, "wb") as cert_file_input:
                cert_file_input.write(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, cert)
                )
            with open(key_file, "wb") as key_file_output:
                key_file_output.write(crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, key)
                )
        except IOError:
            traceback.print_exc()
            return None, None
        return cert_file, key_file

    def sni_callback(self, sslsock, servername, sslctx):
        if servername is None:
            servername = self.CN
        newctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        cert_file, key_file = self.create_cert(servername, self.ca_cert, self.ca_key)
        if cert_file is None or key_file is None:
            return

        newctx.check_hostname = False
        newctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        sslsock.context = newctx
        return

    def _load_cert(self, certpath):
        ca_cert = None
        try:
            with open(certpath, 'rb') as cert_file_input:
                data = cert_file_input.read()
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        except:
            self.logger.error("Failed to load certficate")
        return ca_cert
    
    def _load_private_key(self, keypath):
        try:
            with open(keypath, 'rb') as key_file_input:
                data = key_file_input.read()
            self.privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, data)
        except:
            traceback.print_exc()
            self.privkey = None
        return self.privkey

    def _run_win_certutil(self, argv):
        rc = True
        if sys.platform.startswith('win'):
            try:
                subprocess.check_call(argv, shell=True, stdout=None)
                rc = True
            except subprocess.CalledProcessError:
                self.logger.error('Failed to add root CA')
                rc = False
        return rc

    def _add_root_ca(self, ca_cert_file):
        argv = ['certutil', '-addstore', 'Root', ca_cert_file]
        return self._run_win_certutil(argv)

    def _remove_root_ca(self, cn):
        argv = ['certutil', '-delstore', 'Root', cn]
        return self._run_win_certutil(argv)
    
    
    def __del__(self):
        cert = None
        if self.ca_cert:
            cert = self._load_cert(self.ca_cert)

        if (cert is not None and
             not self.config.get('networkmode', None) == 'multihost' and 
             not self.config.get('static_ca') == 'Yes'): 
            self._remove_root_ca(cert.get_subject().CN)
        shutil.rmtree(self.config.get('cert_dir'), ignore_errors=True)
        return
    

