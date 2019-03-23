

import time
import os
import traceback
import subprocess
import logging
import shutil
import sys
import ssl
from OpenSSL import crypto


class SSLWrapper(object):
    NOT_AFTER_DELTA_SECONDS = 300  * 24 * 60 * 60
    CERT_DIR = "temp_certs"
    CN="fakenet.flare"

    def __init__(self, config):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = config
        self.ca_cert = None
        self.ca_key = None
        
        certdir = self.config.get('certdir', self.CERT_DIR)
        self.logger.info("Cert dir is %s", certdir)
        if certdir is None:
            raise RuntimeError("certdir key is not specified in config")

        if not os.path.isdir(certdir):
            os.makedirs(certdir)

        # generate and add root CA, which is used to sign for other certs:
        if self.config.get('static_ca') == 'Yes':
            self.ca_cert = self.config.get('ca_cert', None)
            self.ca_key = self.config.get('ca_key', None)
        else:
            self.ca_cert, self.ca_key = self.create_cert(self.CN)
        self.logger.info("adding root cert: %s", self.ca_cert)
        if not self._add_root_ca(self.ca_cert):
            raise RuntimeError("Failed to add root ca")
    
    def wrap_socket(self, s):
        self.logger.info('making socket')
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        except:
            self.logger.error(traceback.format_exc())
            self.logger.error("Exception when calling ssl.SSLContext")
            return ctx.wrap_socket(s, server_side=True)
        else:
            ctx.set_servername_callback(self.sni_callback)
            ctx.load_cert_chain(cert_file=self.ca_cert, keyfile=self.ca_key)
            return ctx.wrap_socket(s, server_side=True)

    def create_cert(self, cn, ca_cert=None, ca_key=None, cert_dir=None):
        """
        Create a cert given the common name, a signing CA, CA private key and
        the directory output.

        return: tuple(None, None) on error
                tuple(cert_file_path, key_file_path) on success
        """

        f_selfsign = ca_cert is None or ca_key is None
        if not cert_dir:
            cert_dir = self.CERT_DIR
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
            cert.set_issuer(ca_cert_data.get_subject())
            cert.sign(ca_key_data, "sha1")

        try:
            with open(cert_file, "wb") as cert_file_input:
                cert_file_input.write(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, cert)
                )
            with open(key_file, "wb") as key_file:
                key_file.write(crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, key)
                )
        except:
            traceback.print_exc()
            return None, None
        return cert_file, key_file

    def sni_callback(self, sslsock, servername, sslctx):
        newctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        cert_file, key_file = self.create_cert(servername, self.ca_cert, self.ca_key)
        if cert_file is None or key_file is None:
            return

        newctx.check_hostname = False
        newctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        sslsock.context = newctx
        return

    def _load_cert(self, certpath):
        try:
            with open(certpath, 'rb') as cert_file_input:
                cert_file_input = cert_file.read()
            self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        except:
            self.logger.error(traceback.format_exc())
            self.logger.error("Failed to load certficate")
            self.ca_cert = None
        return self.ca_cert
    
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
        rc = False
        if sys.platform.startswith('win'):
        try:
            subprocess.check_call(argv, shell=True, stdout=None)
            rc = True
        except subprocess.CalledProcessError:
            self.logger.error('Failed to add root CA')
        return rc

    def _add_root_ca(self, ca_cert_file):
        argv = ['certutil', '-addstore', 'Root', ca_cert_file]
        return self._run_win_certutil(argv)

    def _remove_root_ca(self, cn):
        argv = ['certutil', '-delstore', 'Root', cn]
        return self._run_win_certutil(argv)
    
    def _add_root_ca(self, ca_cert_file):
        if not sys.platform.startswith('win'):
            return False
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
    
    def _remove_root_ca(self, cn):
        if not sys.platform.startswith('win'):
            return False
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
    
    def __del__(self):
        cert = self._load_cert(self.ca_cert)
        if cert is not None:
            self._remove_root_ca(cert.get_subject().CN)
        try:
            shutil.rmtree(self.config.get('certdir', self.CERT_DIR))
        except:
            self.logger.warn(traceback.format_exc())
        return
    

