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


class JSONIncludeFilter(logging.Filter):
    """
    Logging filter to filter out any non-json formatted events.
    """
    def filter(self, record):
        return record.getMessage().startswith('{') and record.getMessage().endswith('}')


class JSONExcludeFilter(logging.Filter):
    """
    Logging filter to filter out any json formatted events.
    """
    def filter(self, record):
        return not record.getMessage().startswith('{') and not record.getMessage().endswith('}')

def add_remote_logger(logger, config=None):
    """
    Process remote logger configuration
    :param logger: existing logging instance
    :param config: dictionary object containing remote logger parameters
    :return: true, if remote log handler added successfully, else false.
    """
    logging_level = config['logger_level'] if config.has_key('logger_level') else logging.INFO
    json_only = bool(int(config['json_only'])) if config.has_key('json_only') else True

    if config is None:
        return False
    elif config['logger_type'] == 'splunk':
        ssl_verify = bool(int(config['splunk_cert_verify'])) if config.has_key('splunk_cert_verify') else False
        splunk_source = config['splunk_source'] if config.has_key('splunk_source') else 'FakeNet'
        splunk_sourcetype = config['splunk_sourcetype'] if config.has_key('splunk_sourcetype') else '_json'
        port = int(config['logger_port']) if config.has_key('logger_port') else 8080

        return add_splunk_logger(
            config['logger_host'],
            config['splunk_hectoken'],
            logger,
            logging_level,
            port,
            ssl_verify,
            splunk_source,
            splunk_sourcetype,
            json_only
        )
    else:
        port = int(config['logger_port']) if config.has_key('logger_port') else 514
        proto = config['logger_protocol'] if config.has_key('logger_protocol') else 'TCP'
        return add_syslog_logger(
            config['logger_host'],
            logger,
            logging_level,
            port,
            proto,
            json_only
        )


def add_syslog_logger(host, logger=logging.getLogger('FakeNet Listener'), logging_level=logging.INFO,
                      port=514, proto='TCP', json_only=False,
                      facility=logging.handlers.SysLogHandler.LOG_LOCAL6):
    """
    Attach a remote syslog handler to existing logger

    :param host: IP, hostname or remote logger.  Can also be 'localhost'
    :param logger: logging instance
    :param port: Network port to send logs to
    :param proto: Network protocol supported by remote logger
    :param json_only: Set True to only emit json formatted logs
    :return: True if handler was added, else false
    """

    socket_type = {'UDP': SOCK_DGRAM, 'TCP': SOCK_STREAM }
    try:
        if str(host).startswith('/dev'):
            remote_handler = logging.handlers.SysLogHandler(
                host,
                facility
            )
        else:
            remote_handler = logging.handlers.SysLogHandler(
                        (host, int(port)),
                        facility,
                        socket_type[proto.upper()]
                        )
        try:
            remote_handler.setLevel(logging.getLevelName(logging_level))
        except:
            remote_handler.setLevel(logging.INFO)

        if json_only:
            remote_handler.addFilter(JSONIncludeFilter())
	else:
            remote_handler.addFilter(JSONExcludeFilter())

        logger.addHandler(remote_handler)
        return True
    except Exception as e:
        logger.error("Failed to set Splunk log handler.  Exception: %s" % e)
        return False


def add_splunk_logger(host, hectoken, logger=logging.getLogger('FakeNet Listener'), logging_level=logging.INFO,
                      port=8080, verify=True, source='FakeNet', sourcetype='_json', json_only=True):
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
    :param json_only: Set True to only emit json formatted logs
    :return: True if handler was added, else false
    """

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
            try:
                splunk_handler.setLevel(logging.getLevelName(logging_level))
            except:
                splunk_handler.setLevel(logging.INFO)

            if json_only:
                splunk_handler.addFilter(JSONIncludeFilter())

            logger.addHandler(splunk_handler)
            return True
        except Exception as e:
            logger.error("Failed to set Splunk log handler.  Exception: %s" % e)
            return False
    except Exception as e:
        logger.error("Failed to import Splunk python module (splunk_http_handler), Try 'pip install splunk_http_handler'")
        logger.debug("Exception raised: %s" % e)
        return False


def set_logger(name="FakeNetListener", config=None, logging_level=logging.WARNING):
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
    stream_handler.addFilter(JSONExcludeFilter())
    #logger.addHandler(stream_handler)

    if (config is not None) and (not config.has_key('remotelogging') or config['remotelogging']) == 1:
        for k in config.iterkeys():
            if config[k].__class__ is dict and config[k].has_key('logger_host'):
                add_remote_logger(logger, config[k])
    return logger

