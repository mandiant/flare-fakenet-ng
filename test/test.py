import os
import re
import sys
import time
import errno
import ctypes
import signal
import socket
import pyping
import ftplib
import poplib
import shutil
import hashlib
import smtplib
import logging
import zipfile
import binascii
import platform
import requests
import netifaces
import subprocess
import irc.client
import ConfigParser
from collections import OrderedDict

logger = logging.getLogger('FakeNetTests')
logging.basicConfig(format='%(message)s', level=logging.INFO)

def is_admin():
    result = False
    try:
        result = os.getuid() == 0
    except AttributeError:
        result = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return result

def execute_detached(execute_cmd, winders=False):
    DETACHED_PROCESS = 0x00000008
    cflags = DETACHED_PROCESS if winders else 0
    cfds = False if winders else True
    shl = False if winders else True

    def ign_sigint():
        # Prevent KeyboardInterrupt in FakeNet-NG's console from
        # terminating child processes
        signal.signal(signal.SIGINT, signal.SIG_IGN)


    preexec = None if winders else ign_sigint

    try:
        pid = subprocess.Popen(execute_cmd, creationflags=cflags,
                               shell=shl,
                               close_fds = cfds,
                               preexec_fn = preexec).pid
    except Exception, e:
        logger.info('Error: Failed to execute command: %s', execute_cmd)
        logger.info('       %s', e)
        return None
    else:
        return pid

def get_ips(ipvers):
    """Return IP addresses bound to local interfaces including loopbacks.
    
    Parameters
    ----------
    ipvers : list
        IP versions desired (4, 6, or both); ensures the netifaces semantics
        (e.g. netiface.AF_INET) are localized to this function.
    """
    specs = []
    results = []

    for ver in ipvers:
        if ver == 4:
            specs.append(netifaces.AF_INET)
        elif ver == 6:
            specs.append(netifaces.AF_INET6)
        else:
            raise ValueError('get_ips only supports IP versions 4 and 6')

    for iface in netifaces.interfaces():
        for spec in specs:
            addrs = netifaces.ifaddresses(iface)
            # If an interface only has an IPv4 or IPv6 address, then 6 or 4
            # respectively will be absent from the keys in the interface
            # addresses dictionary.
            if spec in addrs:
                for link in addrs[spec]:
                    if 'addr' in link:
                        results.append(link['addr'])

    return results

def get_external_ip():
    addrs = get_ips([4])
    for addr in addrs:
        if not addr.startswith('127.'):
            return addr

class IrcTester(object):
    def __init__(self, hostname, port=6667):
        self.hostname = hostname
        self.port = port

        self.nick = 'dr_evil'
        self.join_chan = '#whatevs'
        self.clouseau = 'inspector_clouseau'
        self.safehouse = "I'm looking for a safe house."
        self.pub_chan = '#evil_bartenders'
        self.black_market = 'Black Market'

    def _irc_evt_handler(self, srv, evt):
        """Check for each case and set the corresponding success flag."""
        if evt.type == 'join':
            if evt.target.startswith(self.join_chan):
                self.join_ok = True
        elif evt.type == 'welcome':
            if evt.arguments[0].startswith('Welcome to IRC'):
                self.welcome_ok = True
        elif evt.type == 'privmsg':
            if (evt.arguments[0].startswith(self.safehouse) and
                evt.source.startswith(self.clouseau)):
                self.privmsg_ok = True
        elif evt.type == 'pubmsg':
            if (evt.arguments[0].startswith(self.black_market) and
                evt.target == self.pub_chan):
                self.pubmsg_ok = True

    def _irc_script(self, srv):
        """Callback manages individual test cases for IRC."""
        # Clear success flags
        self.welcome_ok = False
        self.join_ok = False
        self.privmsg_ok = False
        self.pubmsg_ok = False

        # This handler should set the success flags in success cases
        srv.add_global_handler('join', self._irc_evt_handler)
        srv.add_global_handler('welcome', self._irc_evt_handler)
        srv.add_global_handler('privmsg', self._irc_evt_handler)
        srv.add_global_handler('pubmsg', self._irc_evt_handler)

        # Issue all commands, indirectly invoking the event handler for each
        # flag

        srv.join(self.join_chan)
        srv.process_data()

        srv.privmsg(self.pub_chan, self.black_market)
        srv.process_data()

        srv.privmsg(self.clouseau, self.safehouse)
        srv.process_data()

        srv.quit()
        srv.process_data()

        if not self.welcome_ok:
            raise FakeNetTestException('Welcome test failed')

        if not self.join_ok:
            raise FakeNetTestException('Join test failed')

        if not self.privmsg_ok:
            raise FakeNetTestException('privmsg test failed')

        if not self.pubmsg_ok:
            raise FakeNetTestException('pubmsg test failed')

        return all([
            self.welcome_ok,
            self.join_ok,
            self.privmsg_ok,
            self.pubmsg_ok
           ])

    def _run_irc_script(self, nm, callback):
        """Connect to server and give control to callback."""
        r = irc.client.Reactor()
        srv = r.server()
        srv.connect(self.hostname, self.port, self.nick)
        retval = callback(srv)
        srv.close()
        return retval

    def test_irc(self):
        return self._run_irc_script('testnm', self._irc_script)

class FakeNetTestException(Exception):
    """A recognizable exception type indicating a known failure state based on
    test criteria. HTTP test uses this, others may in the future, too.
    """
    pass

class FakeNetTester(object):
    """Controller for FakeNet-NG that runs test cases"""

    def __init__(self, settings):
        self.settings = settings
        self.pid_fakenet = None

    def _setStopFlag(self):
        with open(self.settings.stopflag, 'w') as f:
            f.write('1')

    def _clearStopFlag(self):
        if os.path.exists(self.settings.stopflag):
            os.remove(self.settings.stopflag)

    def _confirmFakenetStopped(self):
        return not os.path.exists(self.settings.stopflag)

    def _waitFakenetStopped(self, timeoutsec=None):
        retval = False

        while True:
            if self._confirmFakenetStopped():
                retval = True
                break
            time.sleep(1)

            if timeoutsec is not None:
                timeoutsec -= 1
                if timeoutsec <= 0:
                    break

        return retval

    def _checkPid(self, pid):
        retval = False
        if self.settings.windows:
            PROCESS_TERMINATE = 1
            p = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, 0, pid)
            retval = p != 0;
            if p:
                ctypes.windll.kernel32.CloseHandle(p)
        else:
            # https://stackoverflow.com/questions/568271/how-to-check-if-there-exists-a-process-with-a-given-pid-in-python
            try:
                os.kill(pid, 0)
            except OSError:
                pass
            else:
                retval = True

        return retval

    def _kill(self, pid):
        if self.settings.windows:
            PROCESS_TERMINATE = 1
            # Note, this will get a handle even after the process terminates,
            # in which case TerminateProcess will simply return FALSE.
            p = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, 0, pid)
            if p:
                ok = ctypes.windll.kernel32.TerminateProcess(p, 1)
                ctypes.windll.kernel32.CloseHandle(p)
        else:
            os.kill(pid, signal.SIGKILL)

    def stopFakenetAndWait(self, timeoutsec=None, kill=False):
        if not self.pid_fakenet:
            raise RuntimeError('FakeNet-NG not running, nothing to stop')

        self._setStopFlag()
        stopped_responsive = self._waitFakenetStopped(timeoutsec)

        if not stopped_responsive:
            self._clearStopFlag()

            if kill and self._checkPid(self.pid_fakenet):
                self._kill(self.pid_fakenet)

        self.pid_fakenet = None

        return stopped_responsive

    def executeFakenet(self):
        if self.pid_fakenet:
            raise RuntimeError('FakeNet-NG already running, PID %d' %
                               (self.pid_fakenet))

        os.chdir(self.settings.fndir)

        max_del_attempts = 3
        if os.path.exists(self.settings.logpath):
            for i in range(1, max_del_attempts + 1):
                try:
                    os.remove(self.settings.logpath)
                except WindowsError: # i.e. log file locked by another process
                    logger.warning('Failed to delete %s, attempt %d' %
                                   (self.settings.logpath, i))
                    if i == max_del_attempts:
                        logger.error('Final attempt, re-raising exception')
                        raise
                    else:
                        logger.warning('Retrying in %d seconds...' % (i))
                        time.sleep(i)
                else:
                    break

        cmd = self.settings.genFakenetCmd()
        logger.info('About to run %s' % (cmd))
        self.pid_fakenet = execute_detached(cmd, self.settings.windows)
        if self.pid_fakenet:
            logger.info('FakeNet started with PID %s' % (str(self.pid_fakenet)))

        return (self.pid_fakenet is not None)

    def delConfig(self):
        if os.path.exists(self.settings.configpath):
            os.remove(self.settings.configpath)

    def doTests(self, match_spec):
        self.testGeneral(match_spec)
        self.testNoRedirect(match_spec)
        self.testBlacklistProcess(match_spec)
        self.testWhitelistProcess(match_spec)

    def _printStatus(self, desc, passed):
        status = 'Passed' if passed else 'FAILED'
        punc = '[ + ]' if passed else '[!!!]'
        logger.info('%s %s: %s' % (punc, status, desc))

    def _tryTest(self, desc, callback, args, expected):
        retval = None
        try:
            retval = callback(*args)
        except Exception as e:
            logger.info('Test %s: Uncaught exception of type %s: %s' %
                        (desc, str(type(e)), str(e)))

        passed = (retval == expected)

        return passed

    def _filterMatchingTests(self, tests, matchspec):
        """Remove tests that match negative specifications (regexes preceded by
        a minus sign) or do not match positive specifications (regexes not
        preceded by a minus sign).

        Modifies the contents of the tests dictionary.
        """
        negatives = []
        positives = []

        if len(matchspec):
            # If the user specifies a minus sign before a regular expression,
            # match negatively (exclude any matching tests)
            for spec in matchspec:
                if spec.startswith('-'):
                    negatives.append(spec[1:])
                else:
                    positives.append(spec)

            # Iterating over tests first, match specifications second to
            # preserve the order of the selected tests. Less efficient to
            # compile every regex several times, but less confusing.
            for testname, test in tests.items():

                # First determine if it is to be excluded, in which case,
                # remove it and do not evaluate further match specifications.
                exclude = False
                for spec in negatives:
                    if bool(re.search(spec, testname)):
                        exclude = True
                if exclude:
                    tests.pop(testname)
                    continue

                # If the user ONLY specified negative match specifications,
                # then admit all tests
                if not len(positives):
                    continue

                # Otherwise, only admit if it matches a positive spec
                include = False
                for spec in positives:
                    if bool(re.search(spec, testname)):
                        include = True
                        break
                if not include:
                    tests.pop(testname)

        return

    def _mkzip(self, zip_path, files):
        zip_basename = os.path.splitext(os.path.split(zip_path)[-1])[0]
        with zipfile.ZipFile(zip_path, mode='w') as z:
            for filepath in files:
                filename = os.path.split(filepath)[-1]
                arcname = os.path.join(zip_basename, filename)
                print(arcname)
                z.write(filepath, arcname)

    def _testGeneric(self, label, config, tests, matchspec=[]):
        self._filterMatchingTests(tests, matchspec)
        if not len(tests):
            logger.info('No matching tests')
            return False

        # If doing a multi-host test, then toggle the network mode
        if not self.settings.singlehost:
            config.multiHostMode()

        self.writeConfig(config)

        if self.settings.singlehost:
            if not self.executeFakenet():
                self.delConfig()
                return False

            sec = self.settings.sleep_after_start
            logger.info('Sleeping %d seconds before commencing' % (sec))
            time.sleep(sec)
        else:
            zip_path = os.path.join(self.settings.ancillary_files_dest,
                                    'fakenet-test.zip')
            afpaths = [os.path.join(self.settings.ancillary_files_dest, af)
                       for af in self.settings.ancillary_files]
            files = [self.settings.configpath] + afpaths
            self._mkzip(zip_path, files)

            logger.info('Waiting for you to transition the remote FakeNet-NG')
            logger.info('system to run the %s test suite' % (label))
            logger.info(('***Copy and uncompress this archive on the test '
                        'system: %s') % (zip_path))
            logger.info('')

            while True:
                logger.info('Type \'ok\' to continue, or \'exit\' to stop')
                try:
                    ok = raw_input()
                except EOFError:
                    ok = 'exit'

                if ok.lower() in ['exit', 'quit', 'stop', 'n', 'no']:
                    sys.exit(0)
                elif ok.lower() in ['ok', 'okay', 'go', 'y', 'yes']:
                    break

        logger.info('-' * 79)
        logger.info('Testing')
        logger.info('-' * 79)

        # Do each test
        for desc, (callback, args, expected) in tests.iteritems():
            logger.debug('Testing: %s' % (desc))
            passed = self._tryTest(desc, callback, args, expected)

            # Retry in case of transient error e.g. timeout
            if not passed:
                logger.debug('Retrying: %s' % (desc))
                passed = self._tryTest(desc, callback, args, expected)

            self._printStatus(desc, passed)

            time.sleep(0.5)

        logger.info('-' * 79)
        logger.info('Tests complete')
        logger.info('-' * 79)

        if self.settings.singlehost:
            sec = self.settings.sleep_before_stop
            logger.info('Sleeping %d seconds before transitioning' % (sec))
            time.sleep(sec)

            logger.info('Stopping FakeNet-NG and waiting for it to complete')
            responsive = self.stopFakenetAndWait(15, True)

            if responsive:
                logger.info('FakeNet-NG is stopped')
            else:
                logger.info('FakeNet-NG was no longer running or was stopped forcibly')

            time.sleep(1)

        self.delConfig()

    def _test_sk(self, proto, host, port, teststring=None, expected=None,
                 timeout=5):
        """Test socket-oriented"""
        retval = False
        s = socket.socket(socket.AF_INET, proto)
        s.settimeout(timeout)

        try:
            s.connect((host, port))

            if teststring is None:
                teststring = 'Testing FakeNet-NG'

            if expected is None:
                # RawListener is an echo server unless otherwise configured
                expected = teststring

            remaining = len(teststring)

            while remaining:
                sent = s.send(teststring[-remaining:])
                if sent == 0:
                    raise IOError('Failed to send any bytes')
                remaining -= sent
                
            recvd = ''

            recvd = s.recv(4096)

            retval = (recvd == expected)

        except socket.error as e:
            logger.error('Socket error: %s (%s %s:%d)' %
                         (str(e), proto, host, port))
        except Exception as e:
            logger.error('Non-socket Exception received: %s' % (str(e)))

        return retval

    def _test_icmp(self, host):
        r = pyping.ping(host, count=1)
        return (r.ret_code == 0)

    def _test_ns(self, hostname, expected):
       return (expected == socket.gethostbyname(hostname))

    def _test_smtp_ssl(self, sender, recipient, msg, hostname, port=None, timeout=5):
        smtpserver = smtplib.SMTP_SSL(hostname, port, 'fake.net', None, None, timeout)
        server.sendmail(sender, recipient, msg)
        smtpserver.quit()

    def _test_smtp(self, sender, recipient, msg, hostname, port=None, timeout=5):
        smtpserver = smtplib.SMTP(hostname, port, 'fake.net', timeout)
        smtpserver.sendmail(sender, recipient, msg)
        smtpserver.quit()

        return True

    def _test_pop(self, hostname, port=None, timeout=5):
        pop3server = poplib.POP3(hostname, port, timeout)
        pop3server.user('popuser')
        pop3server.pass_('password')
        msg = pop3server.retr(1)

        response = msg[0]
        lines = msg[1]
        octets = msg[2]

        if not response.startswith('+OK'):
            msg = 'POP3 response does not start with "+OK"'
            logger.error(msg)
            return False

        if not 'Alice' in ''.join(lines):
            msg = 'POP3 message did not contain expected string'
            raise FakeNetTestException(msg)
            return False

        return True
        
    def _util_irc(self, nm, hostname, port, nick, callback):
        r = irc.client.Reactor()
        srv = r.server()
        srv.connect(hostname, port, nick)
        retval = callback(srv)
        srv.close()
        return retval

    def _test_irc(self, hostname, port=6667):
        irc_tester = IrcTester(hostname, port)
        return irc_tester.test_irc()

    def _test_http(self, hostname, port=None, scheme=None, uri=None,
                   teststring=None):
        """Test HTTP Listener"""
        retval = False

        scheme = scheme if scheme else 'http'
        uri = uri.lstrip('/') if uri else 'asdf.html'
        teststring = teststring if teststring else 'H T T P   L I S T E N E R'

        if port:
            url = '%s://%s:%d/%s' % (scheme, hostname, port, uri)
        else:
            url = '%s://%s/%s' % (scheme, hostname, uri)

        try:
            r = requests.get(url, timeout=3)

            if r.status_code != 200:
                raise FakeNetTestException('Status code %d' % (r.status_code))

            if teststring not in r.text:
                raise FakeNetTestException('Test string not in response')

            retval = True

        except requests.exceptions.Timeout as e:
            pass

        except FakeNetTestException as e:
            pass

        return retval

    def _test_ftp(self, hostname, port=None):
        """Note that the FakeNet-NG Proxy listener won't know what to do with
        this client if you point it at some random port, because the client
        listens silently for the server 220 welcome message which doesn't give
        the Proxy listener anything to work with to decide where to forward it.
        """
        fullbuf = ''

        m = hashlib.md5()

        def update_hash(buf):
            m.update(buf)

        f = ftplib.FTP()
        f.connect(hostname, port)
        f.login()
        f.set_pasv(False)
        f.retrbinary('RETR FakeNet.gif', update_hash)
        f.quit()

        digest = m.digest()
        expected = binascii.unhexlify('a6b78c4791dc8110dec6c55f8a756395')

        return (digest == expected)

    def testNoRedirect(self, matchspec=[]):
        config = self.makeConfig(singlehostmode=True, proxied=False, redirectall=False)

        domain_dne = self.settings.domain_dne
        ext_ip = self.settings.ext_ip
        arbitrary = self.settings.arbitrary
        localhost = self.settings.localhost

        tcp = socket.SOCK_STREAM
        udp = socket.SOCK_DGRAM

        t = OrderedDict() # The tests

        t['RedirectAllTraffic disabled external IP @ bound'] = (self._test_sk, (tcp, ext_ip, 1337), True)
        t['RedirectAllTraffic disabled external IP @ unbound'] = (self._test_sk, (tcp, ext_ip, 9999), False)

        t['RedirectAllTraffic disabled arbitrary host @ bound'] = (self._test_sk, (tcp, arbitrary, 1337), False)
        t['RedirectAllTraffic disabled arbitrary host @ unbound'] = (self._test_sk, (tcp, arbitrary, 9999), False)

        t['RedirectAllTraffic disabled named host @ bound'] = (self._test_sk, (tcp, domain_dne, 1337), False)
        t['RedirectAllTraffic disabled named host @ unbound'] = (self._test_sk, (tcp, domain_dne, 9999), False)

        if self.settings.singlehost:
            t['RedirectAllTraffic disabled localhost @ bound'] = (self._test_sk, (tcp, localhost, 1337), True)
            t['RedirectAllTraffic disabled localhost @ unbound'] = (self._test_sk, (tcp, localhost, 9999), False)

        return self._testGeneric('No Redirect', config, t, matchspec)

    def testBlacklistProcess(self, matchspec=[]):
        config = self.makeConfig()
        config.blacklistProcess(self.settings.pythonname)

        arbitrary = self.settings.arbitrary

        tcp = socket.SOCK_STREAM
        udp = socket.SOCK_DGRAM

        t = OrderedDict() # The tests

        if self.settings.singlehost:
            t['Global blacklisted process test'] = (self._test_sk, (tcp, arbitrary, 9999), False)

        return self._testGeneric('Global process blacklist', config, t, matchspec)

    def testWhitelistProcess(self, matchspec=[]):
        config = self.makeConfig()
        config.whitelistProcess(self.settings.pythonname)

        arbitrary = self.settings.arbitrary

        tcp = socket.SOCK_STREAM
        udp = socket.SOCK_DGRAM

        t = OrderedDict() # The tests

        if self.settings.singlehost:
            t['Global whitelisted process test'] = (self._test_sk, (tcp, arbitrary, 9999), True)

        return self._testGeneric('Global process whitelist', config, t, matchspec)

    def testGeneral(self, matchspec=[]):
        config = self.makeConfig()

        domain_dne = self.settings.domain_dne
        ext_ip = self.settings.ext_ip
        arbitrary = self.settings.arbitrary
        blacklistedhost = self.settings.blacklistedhost
        blacklistedtcp = self.settings.blacklistedtcp
        blacklistedudp = self.settings.blacklistedudp
        localhost = self.settings.localhost
        dns_expected = self.settings.dns_expected
        hidden_tcp = self.settings.hidden_tcp
        no_service = self.settings.no_service

        sender = self.settings.sender
        recipient = self.settings.recipient
        smtpmsg = self.settings.smtpmsg

        tcp = socket.SOCK_STREAM
        udp = socket.SOCK_DGRAM

        t = OrderedDict() # The tests

        t['TCP external IP @ bound'] = (self._test_sk, (tcp, ext_ip, 1337), True)
        t['TCP external IP @ unbound'] = (self._test_sk, (tcp, ext_ip, 9999), True)
        t['TCP arbitrary @ bound'] = (self._test_sk, (tcp, arbitrary, 1337), True)
        t['TCP arbitrary @ unbound'] = (self._test_sk, (tcp, arbitrary, 9999), True)
        t['TCP domainname @ bound'] = (self._test_sk, (tcp, domain_dne, 1337), True)
        t['TCP domainname @ unbound'] = (self._test_sk, (tcp, domain_dne, 9999), True)
        if self.settings.singlehost:
            t['TCP localhost @ bound'] = (self._test_sk, (tcp, localhost, 1337), True)
            t['TCP localhost @ unbound'] = (self._test_sk, (tcp, localhost, 9999), False)

        t['TCP custom test static Base64'] = (self._test_sk, (tcp, ext_ip, 1000, 'whatever', '\x0fL\x0aR\x0e'), True)
        t['TCP custom test static string'] = (self._test_sk, (tcp, ext_ip, 1001, 'whatever', 'static string TCP response'), True)
        t['TCP custom test static file'] = (self._test_sk, (tcp, ext_ip, 1002, 'whatever', 'sample TCP raw file response'), True)
        whatever = 'whatever'  # Ensures matching test/expected for TCP dynamic
        t['TCP custom test dynamic'] = (self._test_sk, (tcp, ext_ip, 1003, whatever, ''.join([chr(ord(c)+1) for c in whatever])), True)

        t['UDP external IP @ bound'] = (self._test_sk, (udp, ext_ip, 1337), True)
        t['UDP external IP @ unbound'] = (self._test_sk, (udp, ext_ip, 9999), True)
        t['UDP arbitrary @ bound'] = (self._test_sk, (udp, arbitrary, 1337), True)
        t['UDP arbitrary @ unbound'] = (self._test_sk, (udp, arbitrary, 9999), True)
        t['UDP domainname @ bound'] = (self._test_sk, (udp, domain_dne, 1337), True)
        t['UDP domainname @ unbound'] = (self._test_sk, (udp, domain_dne, 9999), True)
        if self.settings.singlehost:
            t['UDP localhost @ bound'] = (self._test_sk, (udp, localhost, 1337), True)
            t['UDP localhost @ unbound'] = (self._test_sk, (udp, localhost, 9999), False)

        t['UDP custom test static Base64'] = (self._test_sk, (udp, ext_ip, 1000, 'whatever', '\x0fL\x0aR\x0e'), True)
        whatever = 'whatever2'  # Ensures matching test/expected for UDP dynamic
        t['UDP custom test dynamic'] = (self._test_sk, (udp, ext_ip, 1003, whatever, ''.join([chr(ord(c)+1) for c in whatever])), True)

        t['ICMP external IP'] = (self._test_icmp, (ext_ip,), True)
        t['ICMP arbitrary host'] = (self._test_icmp, (arbitrary,), True)
        t['ICMP domainname'] = (self._test_icmp, (domain_dne,), True)

        t['DNS listener test'] = (self._test_ns, (domain_dne, dns_expected), True)
        t['HTTP listener test'] = (self._test_http, (arbitrary,), True)
        # Enable HTTPS when we have either added Server Name Indication and Dynamic CA or have modified `_test_http` to
        # Ignore certificate issues. Here is the error that arises otherwise.
        #   Starting new HTTPS connection (1): 8.8.8.8
        #   Test HTTP listener test with SSL: Uncaught exception of type <class 'requests.exceptions.SSLError'>: [Errno 1] _ssl.c:510: error:14090086:SSL routines:SSL3_GET_SERVER_CERTIFICATE:certificate verify failed
        #   Starting new HTTPS connection (1): 8.8.8.8
        #   Test HTTP listener test with SSL: Uncaught exception of type <class 'requests.exceptions.SSLError'>: [Errno 1] _ssl.c:510: error:14090086:SSL routines:SSL3_GET_SERVER_CERTIFICATE:certificate verify failed
        #   [!!!] FAILED: HTTP listener test with SSL
        # t['HTTP listener test with SSL'] = (self._test_http, (arbitrary, None, 'https'), True)
        t['HTTP custom test by URI'] = (self._test_http, (arbitrary, None, None, '/test.txt', 'Wraps this'), True)
        t['HTTP custom test by hostname'] = (self._test_http, ('some.random.c2.com', None, None, None, 'success'), True)
        t['HTTP custom test by both URI and hostname'] = (self._test_http, ('both_host.com', None, None, '/and_uri.txt', 'Ahoy'), True)
        t['HTTP custom test by both URI and hostname wrong URI'] = (self._test_http, ('both_host.com', None, None, '/not_uri.txt', 'Ahoy'), False)
        t['HTTP custom test by both URI and hostname wrong hostname'] = (self._test_http, ('non_host.com', None, None, '/and_uri.txt', 'Ahoy'), False)
        t['HTTP custom test by ListenerType'] = (self._test_http, ('other.c2.com', 81, None, '/whatever.html', 'success'), True)
        t['HTTP custom test by ListenerType host port negative match'] = (self._test_http, ('other.c2.com', 80, None, '/whatever.html', 'success'), False)
        t['FTP listener test'] = (self._test_ftp, (arbitrary,), True)
        t['POP3 listener test'] = (self._test_pop, (arbitrary, 110), True)
        t['SMTP listener test'] = (self._test_smtp, (sender, recipient, smtpmsg, arbitrary), True)

        # Does not work, SSL error
        t['SMTP SSL listener test'] = (self._test_smtp_ssl, (sender, recipient, smtpmsg, arbitrary), True)

        # Works on Linux, not on Windows
        t['IRC listener test'] = (self._test_irc, (arbitrary,), True)

        t['Proxy listener HTTP test'] = (self._test_http, (arbitrary, no_service), True)
        t['Proxy listener HTTP hidden test'] = (self._test_http, (arbitrary, hidden_tcp), True)

        t['TCP blacklisted host @ unbound'] = (self._test_sk, (tcp, blacklistedhost, 9999), False)
        t['TCP arbitrary @ blacklisted unbound'] = (self._test_sk, (tcp, arbitrary, blacklistedtcp), False)
        t['UDP arbitrary @ blacklisted unbound'] = (self._test_sk, (udp, arbitrary, blacklistedudp), False)

        if self.settings.singlehost:
            t['Listener process blacklist'] = (self._test_http, (arbitrary, self.settings.listener_proc_black), False)
            t['Listener process whitelist'] = (self._test_http, (arbitrary, self.settings.listener_proc_white), True)
            t['Listener host blacklist'] = (self._test_http, (arbitrary, self.settings.listener_host_black), True)
            t['Listener host whitelist'] = (self._test_http, (arbitrary, self.settings.listener_host_black), True)

        return self._testGeneric('General', config, t, matchspec)

    def makeConfig(self, singlehostmode=True, proxied=True, redirectall=True):
        template = self.settings.configtemplate
        return FakeNetConfig(template, singlehostmode, proxied, redirectall)

    def writeConfig(self, config):
        logger.info('Writing config to %s' % (self.settings.configpath))
        config.write(self.settings.configpath)
        for filename in self.settings.ancillary_files:
            path = os.path.join(self.settings.startingpath, filename)
            dest = os.path.join(self.settings.ancillary_files_dest, filename)
            shutil.copyfile(path, dest)

class FakeNetConfig:
    """Convenience class to read/modify/rewrite a configuration template."""

    def __init__(self, path, singlehostmode=True, proxied=True, redirectall=True):
        self.rawconfig = ConfigParser.RawConfigParser()
        self.rawconfig.read(path)

        if singlehostmode:
            self.singleHostMode()
        else:
            self.multiHostMode()

        if not proxied: self.noProxy()

        self.setRedirectAll(redirectall)

    def blacklistProcess(self, process): self.rawconfig.set('Diverter', 'ProcessBlacklist', process)
    def whitelistProcess(self, process): self.rawconfig.set('Diverter', 'ProcessWhitelist', process)

    def setRedirectAll(self, enabled):
        if enabled:
            self.rawconfig.set('Diverter', 'RedirectAllTraffic', 'Yes')
        else:
            self.rawconfig.set('Diverter', 'RedirectAllTraffic', 'No')

    def singleHostMode(self): self.rawconfig.set('Diverter', 'NetworkMode', 'SingleHost')
    def multiHostMode(self): self.rawconfig.set('Diverter', 'NetworkMode', 'MultiHost')

    def noProxy(self):
        self.rawconfig.remove_section('ProxyTCPListener')
        self.rawconfig.remove_section('ProxyUDPListener')
        self.rawconfig.set('Diverter', 'DefaultTCPListener', 'RawTCPListener')
        self.rawconfig.set('Diverter', 'DefaultUDPListener', 'RawUDPListener')

    def write(self, path):
        with open(path, 'w') as f:
            return self.rawconfig.write(f)

class FakeNetTestSettings:
    """Test constants/literals, some of which may vary per OS, etc."""

    def __init__(self, startingpath, singlehost=True):
        # Where am I? Who are you?
        self.platform_name = platform.system()
        self.windows = (self.platform_name == 'Windows')
        self.linux = (self.platform_name.lower().startswith('linux'))

        # Test parameters
        self.singlehost = singlehost
        self.startingpath = startingpath
        self.configtemplate = os.path.join(startingpath, 'template.ini')

        self.ancillary_files_dest = self.genPath('%TEMP%', '/tmp/')
        self.ancillary_files = [
            'custom_responses.ini',
            'CustomProviderExample.py',
            'sample_raw_response.txt',
            'sample_raw_tcp_response.txt',
        ]

        # Paths
        self.configpath = self.genPath('%TEMP%\\fakenet.ini', '/tmp/fakenet.ini')
        self.stopflag = self.genPath('%TEMP%\\stop_fakenet', '/tmp/stop_fakenet')
        self.logpath = self.genPath('%TEMP%\\fakenet.log', '/tmp/fakenet.log')
        self.fakenet = self.genPath('fakenet', 'python fakenet.py')
        self.fndir = self.genPath('.', '$HOME/files/src/flare-fakenet-ng/fakenet')

        # For process blacklisting
        self.pythonname = os.path.basename(sys.executable)

        # Various
        self.ext_ip = get_external_ip()
        self.arbitrary = '8.8.8.8'
        self.blacklistedhost = '6.6.6.6'
        self.blacklistedtcp = 139
        self.blacklistedudp = 67
        self.hidden_tcp =  12345
        self.no_service = 10
        self.listener_proc_black = 8080 # HTTP listener with process blacklist
        self.listener_proc_white = 8081 # HTTP listener with process whitelists
        self.listener_host_black = 8082 # HTTP listener with host blacklist
        self.listener_host_white = 8083 # HTTP listener with host whitelists
        self.localhost = '127.0.0.1'
        self.dns_expected = '192.0.2.123'
        self.domain_dne = 'does-not-exist-amirite.fireeye.com'
        self.sender = 'from-fakenet@example.org'
        self.recipient = 'to-fakenet@example.org'
        self.smtpmsg = 'FakeNet-NG SMTP test email'

        # Behaviors
        self.sleep_after_start = 4
        self.sleep_before_stop = 1

    def genPath(self, winpath, unixypath):
        if self.windows:
            return os.path.expandvars(winpath)
        else:
            return os.path.expandvars(unixypath)

    def genFakenetCmd(self):
        return ('%s -f %s -n -l %s -c %s' %
                (self.fakenet, self.stopflag, self.logpath, self.configpath))

def is_ip(s):
    pat = '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
    return bool(re.match(pat, s))

def main():
    if not is_admin():
        logger.error('Not an admin, exiting...')
        sys.exit(1)

    if len(sys.argv) < 2:
        logger.error('Usage: test.py <where> [matchspec1 [matchspec2 [...] ] ]')
        logger.error('')
        logger.error('Valid where:')
        logger.error('  here')
        logger.error('  Any dot-decimal IP address')
        logger.error('')
        logger.error('Each match specification is a regular expression that')
        logger.error('will be compared against test names, and any matches')
        logger.error('will be included. Because regular expression negative')
        logger.error('matching is complicated to use, you can just prefix')
        logger.error('a match specification with a minus sign to indicate')
        logger.error('that you would like to include only tests that do NOT')
        logger.error('match the expression.')
        sys.exit(1)

    # Validate where
    where = sys.argv[1]

    singlehost = (where.lower() == 'here')

    if not singlehost and not is_ip(where):
        logger.error('Invalid where: %s' % (where))
        sys.exit(1)

    # Will execute only tests matching *match_spec if specified
    match_spec = sys.argv[2:]

    if len(match_spec):
        logger.info('Only running tests that match the following ' +
                    'specifications:')
        for spec in match_spec:
            logger.info('  %s' % (spec))

    # Doit
    startingpath = os.getcwd()
    settings = FakeNetTestSettings(startingpath, singlehost)
    if not singlehost: # <where> was an IP, so record it
        settings.ext_ip = where
    tester = FakeNetTester(settings)
    logger.info('Running with privileges on %s' % (settings.platform_name))
    tester.doTests(match_spec)

if __name__ == '__main__':
    main()
