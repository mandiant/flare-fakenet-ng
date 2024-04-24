# Copyright (C) 2016-2023 Mandiant, Inc. All rights reserved.

import logging

import os
import sys

import threading
import socketserver

import socket
import struct

import urllib.request, urllib.parse, urllib.error
from . import *

EXT_FILE_RESPONSE = {
    '.html': 'FakeNet.html',
    '.png' : 'FakeNet.png',
    '.ico' : 'FakeNet.ico',
    '.jpeg': 'FakeNet.jpg',
    '.exe' : 'FakeNetMini.exe',
    '.pdf' : 'FakeNet.pdf',
    '.xml' : 'FakeNet.html',
    '.txt' : 'FakeNet.txt',
}

OPCODE_RRQ   = b"\x00\x01"
OPCODE_WRQ   = b"\x00\x02"
OPCODE_DATA  = b"\x00\x03"
OPCODE_ACK   = b"\x00\x04"
OPCODE_ERROR = b"\x00\x05"

BLOCKSIZE = 512

class TFTPListener(object):


    def taste(self, data, dport):

        max_filename_size = 128
        max_mode_size = len('netascii')
        max_rrq_wrq_len = max_filename_size + max_mode_size + 4
        min_rrq_wrq_len = 6
        min_data_size = 5
        max_data_size = BLOCKSIZE + 4
        ack_size = 4
        min_error_size = 5 + 1 
        max_error_msg_size = 128
        max_error_size = 5 + max_error_msg_size

        confidence = 1 if dport == 69 else 0

        stripped = data.lstrip()
        if (stripped.startswith(OPCODE_RRQ) or 
                stripped().startswith(OPCODE_WRQ)):
            if len(data) >= min_rrq_wrq_len and len(data) <= max_rrq_wrq_len:
                confidence += 2
        elif stripped.startswith(OPCODE_DATA):
            if len(data) >= min_data_size and len(data) <= max_data_size:
                confidence += 2
        elif stripped.startswith(OPCODE_ACK):
            if len(data) == ack_size:
                confidence += 2
        elif stripped.startswith(OPCODE_ERROR):
            if len(data) >= min_error_size and len(data) <= max_error_size:
                confidence += 2

        return confidence

    def __init__(self,
            config,
            name='TFTPListener',
            logging_level=logging.INFO,
            ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level) 
        self.config = config
        self.name = name
        self.local_ip = config.get('ipaddr')
        self.server = None
        self.name = 'TFTP'
        self.port = self.config.get('port', 69)

        self.logger.debug('Initialized with config:')
        for key, value in config.items():
            self.logger.debug('  %10s: %s', key, value)

        path = self.config.get('tftproot', 'defaultFiles')
        self.tftproot_path = ListenerBase.abs_config_path(path)
        if self.tftproot_path is None:
            self.logger.error('Could not locate tftproot directory: %s', path)
            sys.exit(1)

        self.tftp_file_prefix = self.config.get('tftpfileprefix', 'tftp')

    def start(self):
        self.logger.debug('Starting...')
        # Start listener
        self.server = ThreadedUDPServer((self.local_ip, int(self.config['port'])), ThreadedUDPRequestHandler)

        self.server.logger = self.logger
        self.server.config = self.config
        self.server.tftproot_path = self.tftproot_path
        self.server.tftp_file_prefix = self.tftp_file_prefix

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.debug('Stopping...')
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def acceptDiverterListenerCallbacks(self, diverterListenerCallbacks):
        self.server.diverterListenerCallbacks = diverterListenerCallbacks

class ThreadedUDPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):

        try:
            (data,socket) = self.request

            if not data:
                return

            opcode = data[:2]

            if opcode == OPCODE_RRQ:
                filename, mode = self.parse_rrq_wrq_packet(data)
                self.server.logger.info('Received request to download %s', filename)
                self.handle_rrq(socket, filename.decode('utf-8'))

                # Collect NBIs
                indicator_filename = filename
                if isinstance(filename, bytes):
                    indicator_filename = filename.decode('utf-8')
                nbi = {"Command": "RRQ", "Filename": indicator_filename}
                self.collect_nbi(nbi)

            elif opcode == OPCODE_WRQ:

                filename, mode = self.parse_rrq_wrq_packet(data)
                self.server.logger.info('Received request to upload %s', filename)

                self.handle_wrq(socket, filename)

                # Collect NBIs
                indicator_filename = filename
                if isinstance(filename, bytes):
                    indicator_filename = filename.decode('utf-8')
                nbi = {"Command": "WRQ", "Filename": indicator_filename}
                self.collect_nbi(nbi)

            elif opcode == OPCODE_ACK:

                block_num = struct.unpack('!H', data[2:4])[0]
                self.server.logger.debug('Received ACK for block %d', block_num)

                # Collect NBIs
                nbi = {
                    "Command": "ACK",
                    "Block Number": block_num
                    }
                self.collect_nbi(nbi)

            elif opcode == OPCODE_DATA:

                self.handle_data(socket, data)

            elif opcode == OPCODE_ERROR:

                    error_num = struct.unpack('!H', data[2:4])[0]
                    error_msg = data.decode('utf-8')[4:]

                    self.server.logger.info('Received error message %d:%s', error_num, error_msg)

                    # Collect NBIs
                    nbi = {
                        "Command": "ERROR",
                        "Error Number": error_num,
                        "Error Message": error_msg
                        }
                    self.collect_nbi(nbi)

            else:

                unknown_opcode = struct.unpack('!H', data[:2])[0]
                self.server.logger.error('Unknown opcode: %d', unknown_opcode)

                # Collect NBIs
                nbi = {
                    "Command": "Unknown command",
                    "Opcode": str(unknown_opcode),
                    "Data": data.decode("utf-8")[4:]
                    }
                self.collect_nbi(nbi)

        except Exception as e:
            self.server.logger.error('Error: %s', e)
            raise e

    def handle_data(self, socket, data):

            block_num = struct.unpack('!H', data[2:4])[0]

            if hasattr(self.server, 'filename_path') and self.server.filename_path:

                safe_file = self.server.tftp_file_prefix + "_" + urllib.parse.quote(self.server.filename_path, '')
                
                if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
                    output_dir = os.path.dirname(sys.executable)
                else:
                    output_dir = os.path.dirname(__file__)
                output_file = ListenerBase.safe_join(output_dir, safe_file)
                f = open(output_file, 'ab')
                f.write(data[4:])
                f.close()

                # Collect NBIs
                indicator_data = data
                indicator_filename = self.server.filename_path
                if isinstance(data, bytes):
                    indicator_data = data.decode('utf-8')
                if isinstance(self.server.filename_path, bytes):
                    indicator_filename = self.server.filename_path.decode('utf-8')

                # Send ACK packet for the given block number
                ack_packet = OPCODE_ACK + data[2:4]
                socket.sendto(ack_packet, self.client_address)

            else:
                # Collect NBIs
                indicator_data = data
                indicator_filename = None
                if isinstance(data, bytes):
                    indicator_data = data.decode('utf-8')

                self.server.logger.error('Received DATA packet but don\'t know where to store it.')

            nbi = {"Command": "DATA", "Data": indicator_data[4:], "Filename":
                    indicator_filename}
            self.collect_nbi(nbi)

    def handle_rrq(self, socket, filename):

        filename_path = ListenerBase.safe_join(self.server.tftproot_path,
                                                    filename)

        # If virtual filename does not exist return a default file based on extention
        if not os.path.isfile(filename_path):

            file_basename, file_extension = os.path.splitext(filename)

            # Calculate absolute path to a fake file
            filename_path = ListenerBase.safe_join(self.server.tftproot_path,
                                                        EXT_FILE_RESPONSE.get(file_extension.lower(), 'FakeNetMini.exe'))


        self.server.logger.debug('Sending file %s', filename_path)

        f = open(filename_path, 'rb')

        i = 1

        while True:

            # Read in a buffer of blocksize from the file
            data_block = f.read(BLOCKSIZE)

            if not data_block or len(data_block) == 0:
                break

            data_packet = OPCODE_DATA + struct.pack('!H', i) + data_block
            socket.sendto(data_packet, self.client_address)

            i += 1

        f.close()

    def handle_wrq(self, socket, filename):

        self.server.filename_path = filename

        # Send acknowledgement so the client will begin writing
        ack_packet = OPCODE_ACK + b"\x00\x00"
        socket.sendto(ack_packet, self.client_address)


    def parse_rrq_wrq_packet(self, data):

        filename, mode, _ = data[2:].split(b"\x00", 2)
        return (filename, mode)

    def collect_nbi(self, nbi):
        # Report diverter everytime we capture an NBI
        self.server.diverterListenerCallbacks.logNbi(self.client_address[1],
                nbi, 'UDP', 'TFTP', 'No')

class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    pass

###############################################################################
# Testing code
def test(config):
    pass

def main():
    """
    Run from the flare-fakenet-ng root dir with the following command:

       python2 -m fakenet.listeners.TFTPListener

    """
    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)

    config = {'port': '69', 'protocol': 'udp', 'tftproot': 'defaultFiles'}

    listener = TFTPListener(config)
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
    #test(config)

    listener.stop()

if __name__ == '__main__':
    main()
