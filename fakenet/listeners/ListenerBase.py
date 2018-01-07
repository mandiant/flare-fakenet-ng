import logging
import logging.handlers
from socket import SOCK_DGRAM, SOCK_STREAM
import os


def safe_join(root, path):
    """ 
    Joins a path to a root path, even if path starts with '/', using os.sep
    """ 

    # prepending a '/' ensures '..' does not traverse past the root
    # of the path
    if not path.startswith('/'):
        path = '/' + path
    normpath = os.path.normpath(path)

    return root + normpath


def abs_config_path(path):
    """
    Attempts to return the absolute path of a path from a configuration
    setting.

    First tries just to just take the abspath() of the parameter to see
    if it exists relative to the current working directory.  If that does
    not exist, attempts to find it relative to the 'fakenet' package
    directory. Returns None if neither exists.
    """

    # Try absolute path first
    abspath = os.path.abspath(path)
    if os.path.exists(abspath):
        return abspath

    # Try to locate the location relative to application path
    relpath = os.path.join(os.path.dirname(os.path.dirname(__file__)), path) 

    if os.path.exists(relpath):
        return os.path.abspath(relpath)

    return None


def add_remote_logger(host, logger=logging.getLogger('FakeNet Listener'), port=514, proto='TCP'):
    """
    Attach a remote syslog handler to existing logger

    :param host: IP, hostname or remote logger.  Can also be 'localhost'
    :param logger: logging instance
    :param port: Network port to send logs to
    :param proto: Network protocol supported by remote logger
    :return: Modified logger with remote handler attached
    """
    socket_type = {'UDP': SOCK_DGRAM, 'TCP': SOCK_STREAM }
    return logger.addHandler(
        logging.handlers.SysLogHandler(
            (host, port),
            logging.handlers.SysLogHandler.LOG_DAEMON,
            socket_type[proto.upper()]
        )
    )


def add_splunk_logger(host, hectoken, logger=logging.getLogger('FakeNet Listener'), port=8080, verify=True, source='FakeNet', sourcetype='_json'):
    """
    Attach a remote Splunk HTTP Event Collector handler to existing logger
    http://docs.splunk.com/Documentation/SplunkCloud/latest/Data/UsetheHTTPEventCollector

    :param host: IP, hostname of splunk search head, forwarder or indexer
    :param hectoken: HTTP Event Collector token for authentication.
    :param logger: logging instance
    :param port: HEC port
    :param verify: SSL verification
    :param source: Splunk event source
    :param sourcetype: Splunk event sourcetype.
    :return: Modified logger with remote handler attached
    """
    class JSONFilter(logging.Filter):
        """
        Logging filter to filter out any non-json formatted events.
        """
        def filter(self, record):
            return record.getMessage().startswith('{') and record.getMessage().endswith('}')

    try:
        from splunk_http_handler import SplunkHttpHandler
        try:
            splunk_handler = SplunkHttpHandler(
                                host,
                                hectoken,
                                port=port,
                                source=source,
                                sourcetype=sourcetype,
                                ssl_verify=bool(verify)
                                )
            splunk_handler.addFilter(JSONFilter())
            logger.addHandler(splunk_handler)
        except Exception as e:
            logger.error("Failed to set Splunk log handler.  Exception: %s" % e)
    except Exception as e:
        logger.error("Failed to import Splunk python module (splunk_http_handler), Try 'pip install splunk_http_handler'")
        logger.debug("Exception raised: %s" % e)
    finally:
        return logger


def set_logger(name="FakeNetListener", config=None, logging_level=logging.INFO):
    """
    Set default logger for listeners

    :param name: Unique string to identify the Listener
    :param config: listener_config object updated with containing remotelogger_config
    :param logging_level: logging verbosity
    :return: logger with either splunk or syslog handlers
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging_level)
    logger.propagate = False
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging_level)
    stream_formatter = logging.Formatter('%(asctime)s [%(name)18s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p')
    stream_handler.setFormatter(stream_formatter)
    logger.addHandler(stream_handler)

    if config['enableremotelogger']:
        try:
            if config['logger_type'] == 'splunk':
                add_splunk_logger(
                    config['logger_host'],
                    config['splunk_hectoken'],
                    logger,
                    config['logger_port'],
                    config['splunk_cert_verify'],
                    source=name
                )
            elif config['logger_type'] == 'syslog':
                add_remote_logger(
                    config['logger_host'],
                    logger,
                    int(config['logger_port']),
                    config['logger_protocol']
                )
        except Exception as e:
            logger.warning("Failed to add %s log handler for %s" % (config['logger_type'], name))
            logger.debug("Exception raised: %s") % e
            logger.debug("Config: \n%s") % config

    return logger

