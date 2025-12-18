# Copyright 2025 Google LLC

import socket
import socketserver
import threading
import sys
import glob
import time
import importlib
import queue
import select
import logging
import ssl
from OpenSSL import SSL
from .ssl_utils import ssl_detector, SSLWrapper
from . import *
import os
import traceback

BUF_SZ = 1024


class ProxyListener(object):

    def __init__(
        self,
        config={},
        name="ProxyListener",
        logging_level=logging.DEBUG,
    ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)

        self.config = config
        self.name = name
        self.local_ip = config.get("ipaddr")
        self.server = None
        self.udp_fwd_table = dict()

        self.logger.debug("Starting...")

        self.logger.debug("Initialized with config:")
        for key, value in config.items():
            self.logger.debug("  %10s: %s", key, value)

    def start(self):

        proto = self.config.get("protocol").upper()
        if proto != None:

            if proto == "TCP":

                self.logger.debug("Starting TCP ...")
                config = {
                    "cert_dir": self.config.get("cert_dir", "configs/temp_certs"),
                    "networkmode": self.config.get("networkmode", None),
                    "static_ca": self.config.get("static_ca", "No"),
                    "ca_cert": self.config.get("ca_cert"),
                    "ca_key": self.config.get("ca_key"),
                }
                self.sslwrapper = SSLWrapper(config)
                self.server = ThreadedTCPServer(
                    (self.local_ip, int(self.config.get("port"))), ThreadedTCPRequestHandler
                )
                self.server.sslwrapper = self.sslwrapper

            elif proto == "UDP":

                self.logger.debug("Starting UDP ...")

                self.server = ThreadedUDPServer(
                    (self.local_ip, int(self.config.get("port"))), ThreadedUDPRequestHandler
                )
                self.server.fwd_table = self.udp_fwd_table

            else:
                self.logger.error("Unknown protocol %s" % proto)
                return

        else:
            self.logger.error("Protocol is not defined")
            return

        self.server.config = self.config
        self.server.logger = self.logger
        self.server.local_ip = self.local_ip
        if self.local_ip == "0.0.0.0":
            self.server.local_ip = "localhost"
        self.server.running_listeners = None
        self.server.diverter = None
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        server_ip, server_port = self.server.server_address
        self.logger.debug("%s Server(%s:%d) thread: %s" % (proto, server_ip, server_port, self.server_thread.name))

    def stop(self):
        self.logger.debug("Stopping...")
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def acceptListeners(self, listeners):
        self.server.listeners = listeners

    def acceptDiverter(self, diverter):
        self.server.diverter = diverter

    def acceptDiverterListenerCallbacks(self, diverterListenerCallbacks):
        self.server.diverterListenerCallbacks = diverterListenerCallbacks


class ThreadedTCPClientSocket(threading.Thread):

    def __init__(self, ip, port, listener_q, remote_q, config, log):

        super(ThreadedTCPClientSocket, self).__init__()
        self.ip = ip
        self.port = int(port)
        self.listener_q = listener_q
        self.remote_q = remote_q
        self.config = config
        self.logger = log
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        try:
            self.sock.connect((self.ip, self.port))
            new_sport = self.sock.getsockname()[1]
            return new_sport

        except Exception as e:
            self.logger.debug("Listener socket exception while attempting connection %s" % str(e))

        return None

    def run(self):

        try:
            while True:
                readable, writable, exceptional = select.select([self.sock], [], [], 0.001)
                if not self.remote_q.empty():
                    data = self.remote_q.get()
                    self.sock.send(data)
                if readable:
                    data = self.sock.recv(BUF_SZ)
                    if data:
                        self.listener_q.put(data)
                    else:
                        self.sock.close()
                        sys.exit(1)
        except Exception as e:
            self.logger.debug("Listener socket exception %s" % str(e))


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True


def get_top_listener(config, data, listeners, diverter, orig_src_ip, orig_src_port, proto):

    top_listener = None
    top_confidence = 0
    dport = diverter.getOriginalDestPort(orig_src_ip, orig_src_port, proto)

    for listener in listeners:

        try:
            confidence = listener.taste(data, dport)
            if confidence > top_confidence:
                top_confidence = confidence
                top_listener = listener
        except:
            # Exception occurs if taste() is not implemented for this listener
            pass

    return top_listener


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):

        remote_sock = self.request
        # queue for data received from the listener
        listener_q = queue.Queue()
        # queue for data received from remote
        remote_q = queue.Queue()
        data = None

        try:
            data = remote_sock.recv(BUF_SZ, socket.MSG_PEEK)

            self.server.logger.debug("Received %d bytes.", len(data))
            self.server.logger.debug(
                "%s",
                "-" * 80,
            )
            for line in hexdump_table(data):
                self.server.logger.debug(line)
            self.server.logger.debug(
                "%s",
                "-" * 80,
            )

        except Exception as e:
            self.server.logger.warning("recv() error: %s" % str(e))

        # Is the pkt ssl encrypted?
        # Using a str here instead of bool to match the format returned by
        # configs of other listeners
        is_ssl_encrypted = "No"

        if data:
            if ssl_detector.looks_like_ssl(data):
                is_ssl_encrypted = "Yes"
                self.server.logger.debug("SSL detected")
                ssl_remote_sock = self.server.sslwrapper.wrap_socket(remote_sock)
                data = ssl_remote_sock.recv(BUF_SZ)

            else:
                ssl_remote_sock = None

            orig_src_ip = self.client_address[0]
            orig_src_port = self.client_address[1]

            top_listener = get_top_listener(
                self.server.config, data, self.server.listeners, self.server.diverter, orig_src_ip, orig_src_port, "TCP"
            )

            if top_listener:
                self.server.logger.debug("Likely listener: %s" % top_listener.name)
                listener_sock = ThreadedTCPClientSocket(
                    self.server.local_ip,
                    top_listener.port,
                    listener_q,
                    remote_q,
                    self.server.config,
                    self.server.logger,
                )

                # Get proxy initiated source port and report to diverter
                new_sport = listener_sock.connect()
                if new_sport:
                    self.server.diverterListenerCallbacks.mapProxySportToOrigSport(
                        "TCP", orig_src_port, new_sport, is_ssl_encrypted
                    )

                listener_sock.daemon = True
                listener_sock.start()
                remote_sock.setblocking(0)

                # ssl has no 'peek' option, so we need to process the first
                # packet that is already consumed from the socket
                if ssl_remote_sock:
                    ssl_remote_sock.setblocking(0)
                    remote_q.put(data)

                while True:
                    readable, writable, exceptional = select.select([remote_sock], [], [], 0.001)
                    if readable:
                        try:
                            if ssl_remote_sock:
                                data = ssl_remote_sock.recv(BUF_SZ)
                            else:
                                data = remote_sock.recv(BUF_SZ)
                            if data:
                                remote_q.put(data)
                            else:
                                self.server.logger.debug("Closing remote socket connection")
                                return
                        except Exception as e:
                            self.server.logger.debug("Remote Connection terminated")
                            return
                    if not listener_q.empty():
                        data = listener_q.get()
                        if ssl_remote_sock:
                            ssl_remote_sock.send(data)
                        else:
                            remote_sock.send(data)


class ThreadedUDPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request[0]
        remote_sock = self.request[1]

        self.server.logger.debug("Received UDP packet from %s." % self.client_address[0])

        if data:

            self.server.logger.debug("Received %d bytes.", len(data))
            self.server.logger.debug(
                "%s",
                "-" * 80,
            )
            for line in hexdump_table(data):
                self.server.logger.debug(line)
            self.server.logger.debug(
                "%s",
                "-" * 80,
            )

            orig_src_ip = self.client_address[0]
            orig_src_port = self.client_address[1]

            top_listener = get_top_listener(
                self.server.config, data, self.server.listeners, self.server.diverter, orig_src_ip, orig_src_port, "UDP"
            )

            if top_listener:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.server.local_ip, 0))

                # Get proxy initiated source port and report to diverter
                new_sport = sock.getsockname()[1]
                if new_sport:
                    self.server.diverterListenerCallbacks.mapProxySportToOrigSport(
                        "UDP", orig_src_port, new_sport, "No"
                    )

                sock.sendto(data, (self.server.local_ip, int(top_listener.port)))
                reply = sock.recv(BUF_SZ)
                self.server.logger.debug("Received %d bytes.", len(data))
                sock.close()
                remote_sock.sendto(reply, (orig_src_ip, int(orig_src_port)))
        else:
            self.server.logger.debug("No packet data")


def hexdump_table(data, length=16):

    hexdump_lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_line = " ".join(["%02X" % b for b in chunk])
        ascii_line = "".join([chr(b) if b > 31 and b < 127 else "." for b in chunk])
        hexdump_lines.append("%04X: %-*s %s" % (i, length * 3, hex_line, ascii_line))
    return hexdump_lines


def main():

    logging.basicConfig(
        format="%(asctime)s [%(name)15s] %(message)s", datefmt="%m/%d/%y %I:%M:%S %p", level=logging.DEBUG
    )
    global listeners
    listeners = load_plugins()

    TCP_server = ThreadedTCPServer((sys.argv[1], int(sys.argv[2])), ThreadedTCPRequestHandler)
    TCP_server_thread = threading.Thread(target=TCP_server.serve_forever)
    TCP_server_thread.daemon = True
    TCP_server_thread.start()
    tcp_server_ip, tcp_server_port = TCP_server.server_address
    logger.debug("TCP Server(%s:%d) thread: %s" % (tcp_server_ip, tcp_server_port, TCP_server_thread.name))

    try:
        while True:
            time.sleep(0.001)
    except Exception as e:
        logger.info(e)
        TCP_server.shutdown()
    finally:
        logger.debug("Closing ProxyListener")
        sys.exit(1)
    logger.debug("Exiting")
    TCP_server.shutdown()


if __name__ == "__main__":
    main()
