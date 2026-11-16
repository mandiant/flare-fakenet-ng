# Copyright 2026 Google LLC

import time
import os
import traceback
import subprocess
import logging
import shutil
import sys
import ssl
import random
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from fakenet import listeners
from fakenet.listeners import ListenerBase

class SSLWrapper(object):
    NOT_AFTER_DELTA_SECONDS = 300  * 24 * 60 * 60
    CN="fakenet.flare"

    def __init__(self, config):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = config
        self.ca_cert = None
        self.ca_key = None
        self.ca_crl = None
        self.ca_cn = self.CN

        cert_dir = self.abs_config_path(self.config.get('cert_dir', None))
        if cert_dir is None:
            raise RuntimeError("cert_dir key is not specified in config")

        if not os.path.isdir(cert_dir):
            os.makedirs(cert_dir)

        # generate and add root CA, which is used to sign for other certs:
        if self.config.get('static_ca').lower() == 'yes':
            self.ca_cert = self.abs_config_path(self.config.get('ca_cert', None))
            self.ca_key = self.abs_config_path(self.config.get('ca_key', None))
            self.ca_cn = self._load_cert(self.ca_cert).subject.get_attributes_for_oid(
                NameOID.COMMON_NAME)[0].value
        else:
            self.ca_cert, self.ca_key, self.ca_crl = self.create_cert(self.CN)
        if ( not self.config.get('networkmode', None) == 'multihost' and
             not self.config.get('static_ca').lower() == 'yes'):
            self.logger.debug('adding root cert: %s', self.ca_cert)
            self._add_root_ca(self.ca_cert, self.ca_crl)

    def wrap_socket(self, s):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.options |= ssl.OP_NO_TLSv1
            ctx.options |= ssl.OP_NO_TLSv1_1
        except AttributeError as e:
            self.logger.error('Exception calling ssl.SSLContext: %s', str(e))
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
            cert_dir = self.abs_config_path(self.config.get('cert_dir'))
        else:
            cert_dir = os.path.abspath(cert_dir)

        cert_file = os.path.join(cert_dir, "%s.crt" % (cn))
        key_file = os.path.join(cert_dir, "%s.key" % (cn))
        crl_file = os.path.join(cert_dir, "ca.crl")
        if os.path.exists(cert_file) and os.path.exists(key_file) and os.path.exists(crl_file):
            webroot = self.config.get("webroot")
            if webroot and os.path.exists(webroot):
                web_crl_path = os.path.join(webroot, "ca.crl")
                if not os.path.exists(web_crl_path):
                    shutil.copyfile(crl_file, web_crl_path)
            return cert_file, key_file, crl_file

        if ca_cert is not None and ca_key is not None:
            ca_cert_data = self._load_cert(ca_cert)
            if ca_cert_data is None:
                return None, None, None

            ca_key_data = self._load_private_key(ca_key)
            if ca_key_data is None:
                return None, None, None

        # generate crypto keys:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create a cert. CertificateBuilder always produces an X.509 v3
        # certificate, which is required to use certificate extensions which
        # have proven necessary when working with browsers.
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        crl_dp = x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://fakenet.mandiant.com/ca.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .public_key(key.public_key())
            .serial_number(random.randint(1, 0x31337))
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(seconds=self.NOT_AFTER_DELTA_SECONDS))
        )
        if f_selfsign:
            # root CA cert
            builder = (
                builder.issuer_name(subject)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=False,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(crl_dp, critical=False)
            )
            cert = builder.sign(private_key=key, algorithm=hashes.SHA256())

            crl_builder = x509.CertificateRevocationListBuilder()
            crl_builder = crl_builder.issuer_name(cert.subject)
            crl_builder = crl_builder.last_update(now)
            crl_builder = crl_builder.next_update(now + datetime.timedelta(days=30))

            # Sign and serialize to DER (ASN1)
            crl = crl_builder.sign(private_key=key, algorithm=hashes.SHA256())
            crl_der = crl.public_bytes(serialization.Encoding.DER)

            # write CRL to disk to import into cert store and also serve over HTTP when necessary
            try:
                with open(crl_file, "wb") as f:
                    f.write(crl_der)
                webroot = self.config.get("webroot")
                if webroot and os.path.exists(webroot):
                    with open(os.path.join(webroot, "ca.crl"), "wb") as f:
                        f.write(crl_der)
            except IOError:
                traceback.print_exc()
                return None, None, None

        else:
            # leaf cert for a requested domain
            builder = (
                builder.issuer_name(ca_cert_data.subject)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
                .add_extension(crl_dp, critical=False)
            )
            cert = builder.sign(private_key=ca_key_data, algorithm=hashes.SHA256())

        try:
            with open(cert_file, "wb") as cert_file_input:
                cert_file_input.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(key_file, "wb") as key_file_output:
                key_file_output.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
        except IOError:
            traceback.print_exc()
            return None, None, None
        return cert_file, key_file, crl_file

    def sni_callback(self, sslsock, servername, sslctx):
        if servername is None:
            servername = self.CN
        newctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        newctx.options |= ssl.OP_NO_TLSv1
        newctx.options |= ssl.OP_NO_TLSv1_1
        cert_file, key_file, _ = self.create_cert(servername, self.ca_cert, self.ca_key)
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
            ca_cert = x509.load_pem_x509_certificate(data)
        except (OSError, ValueError) as e:
            self.logger.error("Failed to load certficate: %s", str(e))
        return ca_cert

    def _load_private_key(self, keypath):
        try:
            with open(keypath, 'rb') as key_file_input:
                data = key_file_input.read()
            privkey = serialization.load_pem_private_key(data, password=None)
        except Exception:
            traceback.print_exc()
            privkey = None
        return privkey

    def _run_process(self, argv):
        rc = True
        if sys.platform.startswith('win'):
            try:
                self.logger.debug(f"Running cmd: {argv}")
                subprocess.check_call(argv, shell=True, stdout=None)
                rc = True
            except subprocess.CalledProcessError:
                self.logger.error('Failed to add root CA')
                rc = False
        return rc

    def _add_root_ca(self, ca_cert_file, ca_crl_file):
        argv = ['certutil', '-addstore', 'Root', ca_cert_file]
        installed_cert = self._run_process(argv)
        if not installed_cert:
            return False
        argv = ['certutil', '-addstore', 'CA', ca_crl_file]
        return self._run_process(argv)

    def _remove_root_ca(self, cn):
        argv = ['certutil', '-delstore', 'Root', cn]
        removed = self._run_process(argv)
        if not removed:
            return False
        argv = ['certutil', '-delstore', 'CA', cn]
        return self._run_process(argv)

    def __del__(self):
        if (not self.config.get('networkmode', None) == 'multihost' and 
                not self.config.get('static_ca').lower() == 'yes'): 
            self._remove_root_ca(self.ca_cn)
        shutil.rmtree(self.abs_config_path(self.config.get('cert_dir', None)), ignore_errors=True)
        if self.config.get("webroot"):
            crl = os.path.join(self.config.get("webroot"), "ca.crl")
            if os.path.exists(crl):
                os.remove(crl)
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

        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            abspath = os.path.join(os.getcwd(), path)
        else:
            abspath = os.path.join(os.fspath(Path(__file__).parents[2]), path)

        return abspath
