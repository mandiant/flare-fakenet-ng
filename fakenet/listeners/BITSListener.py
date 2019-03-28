# Based on a simple BITS server by Dor Azouri <dor.azouri@safebreach.com>

import logging

import os
import sys

import threading
import SocketServer
import BaseHTTPServer

import ssl
import socket

import posixpath

import time

import urllib

from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

from . import *

INDENT = '  '

# BITS Protocol header keys
K_BITS_SESSION_ID = 'BITS-Session-Id'
K_BITS_ERROR_CONTEXT = 'BITS-Error-Context'
K_BITS_ERROR_CODE = 'BITS-Error-Code'
K_BITS_PACKET_TYPE = 'BITS-Packet-Type'
K_BITS_SUPPORTED_PROTOCOLS = 'BITS-Supported-Protocols'
K_BITS_PROTOCOL = 'BITS-Protocol'

# HTTP Protocol header keys
K_ACCEPT_ENCODING = 'Accept-Encoding'
K_CONTENT_NAME = 'Content-Name'
K_CONTENT_LENGTH = 'Content-Length'
K_CONTENT_RANGE = 'Content-Range'
K_CONTENT_ENCODING = 'Content-Encoding'

# BITS Protocol header values
V_ACK = 'Ack'

class ThreadedHTTPServer(BaseHTTPServer.HTTPServer):

    def handle_error(self, request, client_address):
        exctype, value = sys.exc_info()[:2]
        self.logger.error('Error: %s', value)

# BITS server errors
class BITSServerHResult(object):
    # default context
    BG_ERROR_CONTEXT_REMOTE_FILE = hex(0x5)
    # official error codes
    BG_E_TOO_LARGE = hex(0x80200020)
    E_INVALIDARG = hex(0x80070057)
    E_ACCESSDENIED = hex(0x80070005)
    ZERO = hex(0x0)  # protocol specification does not give a name for this HRESULT
    # custom error code
    ERROR_CODE_GENERIC = hex(0x1)


class HTTPStatus(object):
    # Successful 2xx
    OK = 200
    CREATED = 201
    # Client Error 4xx
    BAD_REQUEST = 400
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    REQUESTED_RANGE_NOT_SATISFIABLE = 416
    # Server Error 5xx
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501


class BITSServerException(Exception):
    pass

class ClientProtocolNotSupported(BITSServerException):
    def __init__(self, supported_protocols):
        super(ClientProtocolNotSupported, self).__init__("Server supports neither of the requested protocol versions")
        self.requested_protocols = str(supported_protocols)


class ServerInternalError(BITSServerException):
    def __init__(self, internal_exception):
        super(ServerInternalError, self).__init__("Internal server error encountered")
        self.internal_exception = internal_exception


class InvalidFragment(BITSServerException):
    def __init__(self, last_range_end, new_range_start):
        super(ServerInternalError, self).__init__("Invalid fragment received on server")
        self.last_range_end = last_range_end
        self.new_range_start = new_range_start


class FragmentTooLarge(BITSServerException):
    def __init__(self, fragment_size):
        super(FragmentTooLarge, self).__init__("Oversized fragment received on server")
        self.fragment_size = fragment_size


class UploadAccessDenied(BITSServerException):
    def __init__(self):
        super(UploadAccessDenied, self).__init__("Write access to requested file upload is denied")


class BITSUploadSession(object):

    # holds the file paths that has an active upload session
    files_in_use = []

    def __init__(self, absolute_file_path, fragment_size_limit):
        self.fragment_size_limit = fragment_size_limit
        self.absolute_file_path = absolute_file_path
        self.fragments = []
        self.expected_file_length = -1

        # case the file already exists
        if os.path.exists(self.absolute_file_path):
            # case the file is actually a directory
            if os.path.isdir(self.absolute_file_path):
                self._status_code = HTTPStatus.FORBIDDEN
            # case the file is being uploaded in another active session
            elif self.absolute_file_path in BITSUploadSession.files_in_use:
                self._status_code = HTTPStatus.CONFLICT
            # case file exists on server - we overwrite the file with the new upload
            else:
                BITSUploadSession.files_in_use.append(self.absolute_file_path)
                self.__open_file()
        # case file does not exist but its parent folder does exist - we create the file
        elif os.path.exists(os.path.dirname(self.absolute_file_path)):
            BITSUploadSession.files_in_use.append(self.absolute_file_path)
            self.__open_file()
        # case file does not exist nor its parent folder - we don't create the directory tree
        else:
            self._status_code = HTTPStatus.FORBIDDEN 

    def __open_file(self):
        try:
            self.file = open(self.absolute_file_path, "wb")
            self._status_code = HTTPStatus.OK 
        except Exception:
            self._status_code = HTTPStatus.FORBIDDEN

    def __get_final_data_from_fragments(self):
        """
            Combines all accepted fragments' data into one string
        """
        return "".join([frg['data'] for frg in self.fragments])
    
    def get_last_status_code(self):
        return self._status_code

    def add_fragment(self, file_total_length, range_start, range_end, data):
        """
            Applies new fragment received from client to the upload session.
            Returns a boolean: is the new fragment last in session
        """
        # check if fragment size exceeds server limit
        if self.fragment_size_limit < range_end - range_start:
            raise FragmentTooLarge(range_end - range_start)

        # case new fragment is the first fragment in this session
        if self.expected_file_length == -1:
            self.expected_file_length = file_total_length

        last_range_end = self.fragments[-1]['range_end'] if self.fragments else -1
        if last_range_end + 1 < range_start:
            # case new fragment's range is not contiguous with the previous fragment
            # will cause the server to respond with status code 416
            raise InvalidFragment(last_range_end, range_start)
        elif last_range_end + 1 > range_start:
            # case new fragment partially overlaps last fragment
            # BITS protocol states that server should treat only the non-overlapping part
            range_start = last_range_end + 1

        self.fragments.append(
            {'range_start': range_start,
             'range_end': range_end,
              'data': data})
        
        # case new fragment is the first fragment in this session,
        # we write the final uploaded data to file
        if range_end + 1 == self.expected_file_length:
            self.file.write(self.__get_final_data_from_fragments())
            return True

        return False
    
    def close(self):
        self.file.flush()
        self.file.close()
        BITSUploadSession.files_in_use.remove(self.absolute_file_path)


class SimpleBITSRequestHandler(SimpleHTTPRequestHandler):
    
    protocol_version = "HTTP/1.1"
    supported_protocols = ["{7df0354d-249b-430f-820d-3d2a9bef4931}"]  # The only existing protocol version to date
    fragment_size_limit = 100*1024*1024  # bytes

    def do_HEAD(self):
        self.server.logger.info('Received HEAD request')

        # Process request
        self.server.logger.info(self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(INDENT + line)

        # Prepare response
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def __send_response(self, headers_dict={}, status_code=HTTPStatus.OK, data=""):
        """
            Sends server response w/ headers and status code
        """
        self.send_response(status_code)
        for k, v in headers_dict.iteritems():
            self.send_header(k, v)
        self.end_headers()

        self.wfile.write(data)

    def __release_resources(self):
        """
            Releases server resources for a session termination caused by either:
            Close-Session or Cancel-Session
        """
        headers = {
            K_BITS_PACKET_TYPE: V_ACK,
            K_CONTENT_LENGTH: '0'
            }
        
        try:
            session_id = self.headers.get(K_BITS_SESSION_ID, None).lower()
            headers[K_BITS_SESSION_ID] = session_id
            self.server.logger.info("Closing BITS-Session-Id: %s", session_id)
            
            self.sessions[session_id].close()
            self.sessions.pop(session_id, None)

            status_code = HTTPStatus.OK
        except AttributeError:
            self.__send_response(headers, status_code = HTTPStatus.BAD_REQUEST)
            return
        except Exception as e:
            raise ServerInternalError(e)

        self.__send_response(headers, status_code = status_code)

    def _handle_fragment(self):
        """
            Handles a new Fragment packet from the client, adding it to the relevant upload session
        """
        headers = {
            K_BITS_PACKET_TYPE: V_ACK,
            K_CONTENT_LENGTH: '0'
            }

        try:
            # obtain client headers
            session_id = self.headers.get(K_BITS_SESSION_ID, None).lower()
            content_length = int(self.headers.get(K_CONTENT_LENGTH, None))
            content_name = self.headers.get(K_CONTENT_NAME, None)
            content_encoding = self.headers.get(K_CONTENT_ENCODING, None)
            content_range = self.headers.get(K_CONTENT_RANGE, None).split(" ")[-1]
            # set response headers's session id
            headers[K_BITS_SESSION_ID] = session_id
            # normalize fragment details
            crange, total_length = content_range.split("/")
            total_length = int(total_length)
            range_start, range_end = [int(num) for num in crange.split("-")]
        except AttributeError, IndexError:
            self.__send_response(status_code = HTTPStatus.BAD_REQUEST)
            return

        data = self.rfile.read(content_length)

        try:
            is_last_fragment = self.sessions[session_id].add_fragment(
                total_length, range_start, range_end, data)          
            headers['BITS-Received-Content-Range'] = range_end + 1
        except InvalidFragment as e:
            headers[K_BITS_ERROR_CODE] = BITSServerHResult.ZERO
            headers[K_BITS_ERROR_CONTEXT] = BITSServerHResult.BG_ERROR_CONTEXT_REMOTE_FILE
            status_code = HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE
            self.server.logger.error("ERROR processing new fragment (BITS-Session-Id: %s)." + \
                "New fragment range (%d) is not contiguous with last received (%d). context:%s, code:%s, exception:%s", 
                session_id,
                e.new_range_start,
                e.last_range_end,
                headers[K_BITS_ERROR_CONTEXT], 
                headers[K_BITS_ERROR_CODE],
                repr(e))
        except FragmentTooLarge as e:
            headers[K_BITS_ERROR_CODE] = BITSServerHResult.BG_E_TOO_LARGE
            headers[K_BITS_ERROR_CONTEXT] = BITSServerHResult.BG_ERROR_CONTEXT_REMOTE_FILE
            status_code = HTTPStatus.INTERNAL_SERVER_ERROR
            self.server.logger.error("ERROR processing new fragment (BITS-Session-Id: %s)." + \
                "New fragment size (%d) exceeds server limit (%d). context:%s, code:%s, exception:%s", 
                session_id,
                e.fragment_size,
                SimpleBITSRequestHandler.fragment_size_limit,
                headers[K_BITS_ERROR_CONTEXT], 
                headers[K_BITS_ERROR_CODE],
                repr(e))
        except Exception as e:
            raise ServerInternalError(e)
        
        status_code = HTTPStatus.OK
        self.__send_response(headers, status_code = status_code)
    
    def _handle_ping(self):
        """
            Handles Ping packet from client
        """
        self.server.logger.debug("%s RECEIVED", "PING")
        headers = {
            K_BITS_PACKET_TYPE: V_ACK,
            K_BITS_ERROR_CODE : '1',
            K_BITS_ERROR_CONTEXT: '',
            K_CONTENT_LENGTH: '0'
            }
        self.__send_response(headers, status_code = HTTPStatus.OK)

    def __get_current_session_id(self):
        return str(hash((self.connection.getpeername()[0], self.path)))

    def _handle_cancel_session(self):
        self.server.logger.debug("%s RECEIVED", "CANCEL-SESSION")
        return self.__release_resources()
    
    def _handle_close_session(self):
        self.server.logger.debug("%s RECEIVED", "CLOSE-SESSION")
        return self.__release_resources()
    

    def _handle_create_session(self):
        """
            Handles Create-Session packet from client. Creates the UploadSession.
            The unique ID that identifies a session in this server is a hash of the client's address and requested path.
        """
        self.server.logger.debug("%s RECEIVED", "CREATE-SESSION")

        headers = {
            K_BITS_PACKET_TYPE: V_ACK,
            K_CONTENT_LENGTH: '0'
            }
        
        if not getattr(self, "sessions", False):
            self.sessions = dict()
        try:
            # check if server's protocol version is supported in client
            client_supported_protocols = \
                self.headers.get(K_BITS_SUPPORTED_PROTOCOLS, None).lower().split(" ")
            protocols_intersection = set(client_supported_protocols).intersection(
                SimpleBITSRequestHandler.supported_protocols)

            # case mutual supported protocol is found
            if protocols_intersection:
                headers[K_BITS_PROTOCOL] = list(protocols_intersection)[0]

                safe_path = self.server.bits_file_prefix + '_' + urllib.quote(self.path, '')
                absolute_file_path = ListenerBase.safe_join(os.getcwd(), safe_path)

                session_id = self.__get_current_session_id()
                self.server.logger.info("Creating BITS-Session-Id: %s", session_id)
                if session_id not in self.sessions:
                    self.sessions[session_id] = BITSUploadSession(absolute_file_path, SimpleBITSRequestHandler.fragment_size_limit)
                
                headers[K_BITS_SESSION_ID] = session_id
                status_code = self.sessions[session_id].get_last_status_code()
                if status_code == HTTPStatus.FORBIDDEN:
                    raise UploadAccessDenied()
            # case no mutual supported protocol is found
            else:
                raise ClientProtocolNotSupported(client_supported_protocols)
        except AttributeError:
            self.__send_response(headers, status_code = HTTPStatus.BAD_REQUEST)
            return
        except ClientProtocolNotSupported as e:
            status_code = HTTPStatus.BAD_REQUEST
            headers[K_BITS_ERROR_CODE] = BITSServerHResult.E_INVALIDARG
            headers[K_BITS_ERROR_CONTEXT] = BITSServerHResult.BG_ERROR_CONTEXT_REMOTE_FILE
            self.server.logger.error("ERROR creating new session - protocol mismatch (%s). context:%s, code:%s, exception:%s", 
                e.requested_protocols,
                headers[K_BITS_ERROR_CONTEXT], 
                headers[K_BITS_ERROR_CODE],
                repr(e))
        except UploadAccessDenied as e:
            headers[K_BITS_ERROR_CODE] = BITSServerHResult.E_ACCESSDENIED
            headers[K_BITS_ERROR_CONTEXT] = BITSServerHResult.BG_ERROR_CONTEXT_REMOTE_FILE
            self.lserver.logger.error("ERROR creating new session - Access Denied. context:%s, code:%s, exception:%s", 
                headers[K_BITS_ERROR_CONTEXT], 
                headers[K_BITS_ERROR_CODE],
                repr(e))
        except Exception as e:
            raise ServerInternalError(e)
            

        if status_code == HTTPStatus.OK or status_code == HTTPStatus.CREATED:
            headers[K_ACCEPT_ENCODING] = 'identity'
        
        self.__send_response(headers, status_code = status_code)

    def do_BITS_POST(self):
        headers = {}
        bits_packet_type = self.headers.getheaders(K_BITS_PACKET_TYPE)[0].lower()
        try:
            do_function = getattr(self, "_handle_%s" % bits_packet_type.replace("-", "_"))
            try:
                do_function()
                return
            except ServerInternalError as e:
                status_code = HTTPStatus.INTERNAL_SERVER_ERROR
                headers[K_BITS_ERROR_CODE] = BITSServerHResult.ERROR_CODE_GENERIC
        except AttributeError as e:
            # case an Unknown BITS-Packet-Type value was received by the server
            status_code = HTTPStatus.BAD_REQUEST
            headers[K_BITS_ERROR_CODE] = BITSServerHResult.E_INVALIDARG
        
        headers[K_BITS_ERROR_CONTEXT] = BITSServerHResult.BG_ERROR_CONTEXT_REMOTE_FILE
        self.server.logger.error("Internal BITS Server Error. context:%s, code:%s, exception:%s", 
            headers[K_BITS_ERROR_CONTEXT], 
            headers[K_BITS_ERROR_CODE],
            repr(e.internal_exception))
        self.__send_response(headers, status_code = status_code)

class BITSListener(object):

    def taste(self, data, dport):
        request_methods = ['BITS_POST',]

        confidence = 1 if dport in [80, 443] else 0

        for method in request_methods:
            if data.lstrip().startswith(method):
                confidence += 2
                continue

        return confidence

    def __init__(
            self,
            config={},
            name='BITSListener',
            logging_level=logging.DEBUG,
            running_listeners=None
            ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)

        self.config = config
        self.name = name
        self.local_ip = config.get('ipaddr')
        self.server = None
        self.running_listeners = running_listeners
        self.NAME = 'BITS'
        self.PORT = self.config.get('port')

        self.logger.info('Starting...')

        self.logger.debug('Initialized with config:')
        for key, value in config.iteritems():
            self.logger.debug('  %10s: %s', key, value)

        self.bits_file_prefix = self.config.get('bitsfileprefix', 'bits')

    def start(self):
        self.logger.debug('Starting...')
        self.server = ThreadedHTTPServer((self.local_ip, int(self.config.get('port'))), SimpleBITSRequestHandler)
        self.server.logger = self.logger
        self.server.bits_file_prefix = self.bits_file_prefix
        self.server.config = self.config

        if self.config.get('usessl') == 'Yes':
            self.logger.debug('Using SSL socket.')

            keyfile_path = ListenerBase.abs_config_path('privkey.pem')
            if keyfile_path is None:
                self.logger.error('Could not locate privkey.pem')
                sys.exit(1)

            certfile_path = ListenerBase.abs_config_path('server.pem')
            if certfile_path is None:
                self.logger.error('Could not locate certfile.pem')
                sys.exit(1)

            self.server.socket = ssl.wrap_socket(self.server.socket, keyfile=keyfile_path, certfile=certfile_path, server_side=True, ciphers='RSA')

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()        

    def stop(self):
        self.logger.info('Stopping...')
        if self.server:
            self.server.shutdown()
            self.server.server_close()

def test(config):
    pass

def main():
    """
    Run from the flare-fakenet-ng root dir with the following command:

       python2 -m self.BITSListener

    """
    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)
    
    config = {'port': '80', 'usessl': 'No' }

    listener = BITSListener(config)
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
