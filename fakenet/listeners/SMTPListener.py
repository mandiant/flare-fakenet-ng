# Copyright 2025 Google LLC

import logging

import sys
import os

import threading
import socketserver

import ssl
import socket

from . import *


class SMTPListener(object):

    def taste(self, data, dport):

        # Once the TCP connection has been established, the server initiates
        # the conversation with '220' message. However, if the client connects
        # to a nonstandard port there is no way for the proxy to know that
        # SMTP is the protocol until the client sends a message.
        commands = [
            b"HELO",
            b"EHLO",
            b"MAIL FROM",
            b"RCPT TO",
            b"TURN",
            b"ATRN",
            b"SIZE",
            b"ETRN",
            b"PIPELINING",
            b"CHUNKING",
            b"DATA",
            b"DSN",
            b"RSET",
            b"VRFY",
            b"HELP",
            b"QUIT",
            b"X-EXPS GSSAPI",
            b"X-EXPS=LOGIN",
            b"X-EXCH50",
            b"X-LINK2STATE",
        ]
        ports = [25, 587, 465]
        confidence = 1 if dport in ports else 0

        for command in commands:
            if data.lstrip().startswith(command):
                confidence += 2
                continue

        return confidence

    def __init__(
        self,
        config,
        name="SMTPListener",
        logging_level=logging.INFO,
    ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)

        self.config = config
        self.name = name
        self.local_ip = config.get("ipaddr")
        self.server = None
        self.name = "SMTP"
        self.port = self.config.get("port", 25)

        self.logger.debug("Starting...")

        self.logger.debug("Initialized with config:")
        for key, value in config.items():
            self.logger.debug("  %10s: %s", key, value)

    def start(self):
        self.logger.debug("Starting...")
        self.server = ThreadedTCPServer((self.local_ip, int(self.config["port"])), ThreadedTCPRequestHandler)

        if self.config.get("usessl") == "Yes":
            self.logger.debug("Using SSL socket")

            keyfile_path = "listeners/ssl_utils/privkey.pem"
            keyfile_path = ListenerBase.abs_config_path(keyfile_path)
            if keyfile_path is None:
                self.logger.error("Could not locate %s", keyfile_path)
                sys.exit(1)

            certfile_path = "listeners/ssl_utils/server.pem"
            certfile_path = ListenerBase.abs_config_path(certfile_path)
            if certfile_path is None:
                self.logger.error("Could not locate %s", certfile_path)
                sys.exit(1)

            self.server.socket = ssl.wrap_socket(
                self.server.socket, keyfile="privkey.pem", certfile="server.pem", server_side=True, ciphers="RSA"
            )

        self.server.logger = self.logger
        self.server.config = self.config

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.debug("Stopping...")
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def acceptDiverterListenerCallbacks(self, diverterListenerCallbacks):
        self.server.diverterListenerCallbacks = diverterListenerCallbacks


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):

        # Timeout connection to prevent hanging
        self.request.settimeout(int(self.server.config.get("timeout", 5)))

        try:

            self.request.sendall(
                b"%s\r\n" % self.server.config.get("banner", "220 FakeNet SMTP Service Ready").encode()
            )
            while True:
                data = self.request.recv(4096)
                for line in data.split(b"\n"):
                    self.server.logger.debug(line)

                command = data[:4].decode("utf-8").upper()
                args = data[4:].decode("utf-8").strip()

                if command == "":
                    break

                elif command in ["HELO", "EHLO"]:
                    self.request.sendall(b"250 evil.com\r\n")

                elif command in ["MAIL", "RCPT", "NOOP", "RSET"]:
                    self.request.sendall(b"250 OK\r\n")

                elif command == "QUIT":
                    self.request.sendall(b"221 evil.com bye\r\n")

                elif command == "DATA":
                    self.request.sendall(b"354 start mail input, end with <CRLF>.<CRLF>\r\n")

                    mail_data = b""
                    while True:
                        mail_data_chunk = self.request.recv(4096)

                        if not mail_data_chunk:
                            break

                        mail_data += mail_data_chunk

                        if b"\r\n.\r\n" in mail_data:
                            break

                    self.server.logger.info("Received mail data.")
                    for line in mail_data.split(b"\n"):
                        self.server.logger.info(line)

                    self.request.sendall(b"250 OK\r\n")

                    # Collect NBIs
                    # Mail data can be long. Let's capture the first line of the
                    # data for NBI.
                    nbi = {"Command": command, "Mail Data": mail_data.decode("utf-8").split("\n")[0]}
                    self.collect_nbi(nbi)

                else:
                    self.request.sendall(b"503 Command not supported\r\n")

                # Collect NBIs
                if command != "DATA":
                    args = None if args == "" else args
                    nbi = {"Command": command, "Args": args}
                    self.collect_nbi(nbi)

        except socket.timeout:
            self.server.logger.warning("Connection timeout")

        except socket.error as msg:
            self.server.logger.error("Error: %s", msg.strerror or msg)

        except Exception as e:
            self.server.logger.error("Error: %s", e)

    def collect_nbi(self, nbi):
        # Report diverter everytime we capture an NBI
        self.server.diverterListenerCallbacks.logNbi(
            self.client_address[1], nbi, "TCP", "SMTP", self.server.config.get("usessl")
        )


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


###############################################################################
# Testing code
def test(config):

    import smtplib

    logger = logging.getLogger("SMTPListenerTest")

    server = smtplib.SMTP_SSL("localhost", config.get("port", 25))

    message = "From: test@test.com\r\nTo: test@test.com\r\n\r\nTest message\r\n"

    logger.info("Testing email request.")
    logger.info("-" * 80)
    server.set_debuglevel(1)
    server.sendmail("test@test.com", "test@test.com", message)
    server.quit()
    logger.info("-" * 80)


def main():
    logging.basicConfig(
        format="%(asctime)s [%(name)15s] %(message)s", datefmt="%m/%d/%y %I:%M:%S %p", level=logging.DEBUG
    )

    config = {"port": "25", "usessl": "Yes", "timeout": 10}

    listener = SMTPListener(config)
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


if __name__ == "__main__":
    main()
