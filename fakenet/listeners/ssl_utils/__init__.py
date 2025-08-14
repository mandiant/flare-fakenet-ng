# Copyright 2025 Google LLC

import time
import os
import traceback
import subprocess
import logging
import shutil
import sys
import ssl
import random
from pathlib import Path
from OpenSSL import crypto

from fakenet import listeners
from fakenet.listeners import ListenerBase


class SSLWrapper(object):
    NOT_AFTER_DELTA_SECONDS = 300 * 24 * 60 * 60
    CN = "fakenet.flare"

    def __init__(self, config):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = config
        self.ca_cert = None
        self.ca_key = None
        self.ca_cn = self.CN

        cert_dir = self.abs_config_path(self.config.get("cert_dir", None))
        if cert_dir is None:
            raise RuntimeError("cert_dir key is not specified in config")

        if not os.path.isdir(cert_dir):
            os.makedirs(cert_dir)

        # generate and add root CA, which is used to sign for other certs:
        if self.config.get("static_ca").lower() == "yes":
            self.ca_cert = self.abs_config_path(self.config.get("ca_cert", None))
            self.ca_key = self.abs_config_path(self.config.get("ca_key", None))
            self.ca_cn = self._load_cert(self.ca_cert).get_subject().CN
        else:
            self.ca_cert, self.ca_key = self.create_cert(self.CN)
        if (
            not self.config.get("networkmode", None) == "multihost"
            and not self.config.get("static_ca").lower() == "yes"
        ):
            self.logger.debug("adding root cert: %s", self.ca_cert)
            self._add_root_ca(self.ca_cert)

    def wrap_socket(self, s):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.options |= ssl.OP_NO_TLSv1
            ctx.options |= ssl.OP_NO_TLSv1_1
        except AttributeError as e:
            self.logger.error("Exception calling ssl.SSLContext: %s", str(e))
        else:
            ctx.sni_callback = self.sni_callback
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
        if not cert_dir:
            cert_dir = self.abs_config_path(self.config.get("cert_dir"))
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

        # Setting certificate version to 3. This is required to use certificate
        # extensions which have proven necessary when working with browsers
        cert.set_version(2)
        cert.get_subject().C = "US"
        cert.get_subject().CN = cn
        cert.set_serial_number(random.randint(1, 0x31337))
        now = time.time() / 1000000
        na = int(now + self.NOT_AFTER_DELTA_SECONDS)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(na)
        cert.set_pubkey(key)
        if f_selfsign:
            extensions = [
                crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
            ]
            cert.set_issuer(cert.get_subject())
            cert.add_extensions(extensions)
            cert.sign(key, "sha256")
        else:
            alt_name = b"DNS:" + cn.encode()
            extensions = [
                crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
                crypto.X509Extension(b"subjectAltName", False, alt_name),
            ]
            cert.set_issuer(ca_cert_data.get_subject())
            cert.add_extensions(extensions)
            cert.sign(ca_key_data, "sha256")

        try:
            with open(cert_file, "wb") as cert_file_input:
                cert_file_input.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            with open(key_file, "wb") as key_file_output:
                key_file_output.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        except IOError:
            traceback.print_exc()
            return None, None
        return cert_file, key_file

    def sni_callback(self, sslsock, servername, sslctx):
        if servername is None:
            servername = self.CN
        newctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        newctx.options |= ssl.OP_NO_TLSv1
        newctx.options |= ssl.OP_NO_TLSv1_1
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
            with open(certpath, "rb") as cert_file_input:
                data = cert_file_input.read()
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        except crypto.Error as e:
            self.logger.error("Failed to load certficate: %s", str(e))
        return ca_cert

    def _load_private_key(self, keypath):
        try:
            with open(keypath, "rb") as key_file_input:
                data = key_file_input.read()
            privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, data)
        except Exception:
            traceback.print_exc()
            privkey = None
        return privkey

    def _run_process(self, argv):
        rc = True
        if sys.platform.startswith("win"):
            try:
                subprocess.check_call(argv, shell=True, stdout=None)
                rc = True
            except subprocess.CalledProcessError:
                self.logger.error("Failed to add root CA")
                rc = False
        return rc

    def _add_root_ca(self, ca_cert_file):
        argv = ["certutil", "-addstore", "Root", ca_cert_file]
        return self._run_process(argv)

    def _remove_root_ca(self, cn):
        argv = ["certutil", "-delstore", "Root", cn]
        return self._run_process(argv)

    def __del__(self):
        if (
            not self.config.get("networkmode", None) == "multihost"
            and not self.config.get("static_ca").lower() == "yes"
        ):
            self._remove_root_ca(self.ca_cn)
        shutil.rmtree(self.abs_config_path(self.config.get("cert_dir", None)), ignore_errors=True)
        return

    def abs_config_path(self, path):
        """
        Attempts to return the absolute path of a path from a configuration
        setting.
        """

        # Try absolute path first
        abspath = os.path.abspath(path)
        if os.path.exists(abspath):
            return abspath

        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            abspath = os.path.join(os.getcwd(), path)
        else:
            abspath = os.path.join(os.fspath(Path(__file__).parents[2]), path)

        return abspath
