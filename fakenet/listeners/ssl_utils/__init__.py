

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
    
    def initialize(self):
        certdir = self.config.get('certdir', self.CERT_DIR)
        self.logger.error("Cert dir is %s", certdir)
        if certdir is None:
            return False
        if not os.path.isdir(certdir):
            os.makedirs(certdir)

        # generate and add root CA, which is used to sign for other certs:
        if self.config.get('static_ca') == 'Yes':
            self.ca_cert = self.config.get('ca_cert', None)
            self.ca_key = self.config.get('ca_key', None)
        else:
            cn = self.CN
            if cn is None:
                return False
            self.ca_cert, self.ca_key = self.create_cert(cn)
        self.logger.error("adding root cert: %s", self.ca_cert)
        return self._add_root_ca(self.ca_cert)
    
    def wrap_socket(self, s):
        self.logger.error('making socket')
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        except:
            self.logger.error(traceback.format_exc())
            self.logger.error("Exception when calling ssl.SSLContext")
            return ctx.wrap_socket(s, server_side=True)
        else:
            ctx.set_servername_callback(self.sni_callback)
            ctx.load_cert_chain(certfile=self.ca_cert, keyfile=self.ca_key)
            return ctx.wrap_socket(s, server_side=True)

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
            cacert = self._load_cert(ca_cert)
            if cacert is None:
                return None, None

            cakey = self._load_private_key(ca_key)
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

    def sni_callback(self, sslsock, servername, sslctx):
        newctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        certfile, keyfile = self.create_cert(servername, self.ca_cert, self.ca_key)
        if certfile is None or keyfile is None:
            return None

        newctx.check_hostname = False
        newctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        sslsock.context = newctx
        return None

    def _load_cert(self, certpath):
        try:
            with open(certpath, 'rb') as certfile:
                data = certfile.read()
            self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        except:
            traceback.format_exc()
            self.ca_cert = None
        return self.ca_cert
    
    def _load_private_key(self, keypath):
        try:
            with open(keypath, 'rb') as keyfile:
                data = keyfile.read()
            self.privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, data)
        except:
            traceback.print_exc()
            self.privkey = None
        return self.privkey
    
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
            traceback.print_exc()
        return
    

