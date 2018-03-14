import os
import sys
import time
import ctypes
import signal
import socket
import pyping
import ftplib
import hashlib
import logging
import binascii
import platform
import requests
import netifaces
import subprocess
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

    # import pdb
    # pdb.set_trace()
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

class FakeNetTestException(Exception):
    """A recognizable exception type indicating a known failure state based on
    test criteria. HTTP test uses this, others may in the future, too.
    """
    pass

class FakeNetTester:
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
                                   (self.settings.configpath, i))
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

    def doTests(self):
        self.testGeneral()
        self.testNoRedirect()
        self.testBlacklistProcess()
        self.testWhitelistProcess()

    def _printStatus(self, desc, passed):
        status = 'Passed' if passed else 'FAILED'
        punc = '[ + ]' if passed else '[!!!]'
        logger.info('%s %s: %s' % (punc, status, desc))

    def _tryTest(self, desc, callback, args, expected):
        retval = None
        try:
            retval = callback(*args)
        except Exception as e:
            logger.info('Uncaught exception in test %s: %s' % (desc, str(e)))

        passed = (retval == expected)

        return passed

    def _testGeneric(self, config, tests):
        self.writeConfig(config)

        if not self.executeFakenet():
            self.delConfig()
            return False

        sec = self.settings.sleep_after_start
        logger.info('Sleeping %d seconds before commencing' % (sec))
        time.sleep(sec)

        logger.info('-' * 79)
        logger.info('Testing')
        logger.info('-' * 79)

        for desc, (callback, args, expected) in tests.iteritems():
            logger.debug('Testing: %s' % (desc))
            passed = self._tryTest(desc, callback, args, expected)
            if not passed:
                logger.debug('Retrying: %s' % (desc))
                passed = self._tryTest(desc, callback, args, expected)

            self._printStatus(desc, passed)

            time.sleep(0.5)

        logger.info('-' * 79)
        logger.info('Tests complete')
        logger.info('-' * 79)

        sec = self.settings.sleep_before_stop
        logger.info('Sleeping %d seconds before transitioning' % (sec))
        time.sleep(sec)

        logger.info('Stopping FakeNet-NG and waiting for it to complete')
        responsive = self.stopFakenetAndWait(10, True)

        if responsive:
            logger.info('FakeNet-NG is stopped')
        else:
            logger.info('FakeNet-NG was no longer running or was stopped forcibly')

        time.sleep(1)

        self.delConfig()

    def _test_sk(self, proto, host, port, timeout=5):
        """Test socket-oriented"""
        retval = False
        s = socket.socket(socket.AF_INET, proto)
        s.settimeout(timeout)

        try:
            s.connect((host, port))

            teststring = 'Testing FakeNet-NG'
            remaining = len(teststring)

            while remaining:
                sent = s.send(teststring)
                if sent == 0:
                    raise IOError('Failed to send all bytes')
                remaining -= sent
                
            recvd = ''
            remaining = len(teststring)

            while remaining:
                chunk = s.recv(remaining)
                if chunk == '':
                    raise IOError('Failed to receive all bytes')
                remaining -= len(chunk)
                recvd += chunk

            retval = (recvd == teststring)

        except socket.error as e:
            logger.error('Socket error: %s' % (str(e)))
        except Exception as e:
            logger.error('Non-socket Exception received: %s' % (str(e)))

        return retval

    def _test_icmp(self, host):
        r = pyping.ping(host, count=1)
        return (r.ret_code == 0)

    def _test_ns(self, hostname, expected):
       return (expected == socket.gethostbyname(hostname))

    def _test_http(self, hostname, port=None):
        """Test HTTP Listener"""
        retval = False

        if port:
            url = 'http://%s:%d/asdf.html' % (hostname, port)
        else:
            url = 'http://%s/asdf.html' % (hostname)

        try:
            r = requests.get(url, timeout=3)

            if r.status_code != 200:
                raise FakeNetTestException('Status code %d' % (r.status_code))

            teststring = 'H T T P   L I S T E N E R'
            if teststring not in r.text:
                raise FakeNetTestException('Test string not in response')

            retval = True

        except requests.exceptions.Timeout as e:
            pass

        except FakeNetTestException as e:
            pass

        return retval

    def _test_ftp(self, hostname, port=None):
        """Note that the FakeNet-NG Proxy listener won't know what to do with this client
        if you point it at some random port, because the client listens
        silently for the server 220 welcome message which doesn't give the
        Proxy listener anything to work with to decide where to forward it.
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

    def testNoRedirect(self):
        config = self.makeConfig(singlehostmode=True, proxied=False, redirectall=False)

        domain_dne = self.settings.domain_dne
        ext_ip = self.settings.ext_ip
        arbitrary = self.settings.arbitrary
        localhost = self.settings.localhost

        tcp = socket.SOCK_STREAM
        udp = socket.SOCK_DGRAM

        t = OrderedDict() # The tests

        t['RedirectAllTraffic disabled local external IP @ bound'] = (self._test_sk, (tcp, ext_ip, 1337), True)
        t['RedirectAllTraffic disabled local external IP @ unbound'] = (self._test_sk, (tcp, ext_ip, 9999), False)

        t['RedirectAllTraffic disabled arbitrary host @ bound'] = (self._test_sk, (tcp, arbitrary, 1337), True)
        t['RedirectAllTraffic disabled arbitrary host @ unbound'] = (self._test_sk, (tcp, arbitrary, 9999), False)

        t['RedirectAllTraffic disabled named host @ bound'] = (self._test_sk, (tcp, domain_dne, 1337), True)
        t['RedirectAllTraffic disabled named host @ unbound'] = (self._test_sk, (tcp, domain_dne, 9999), False)

        t['RedirectAllTraffic disabled localhost @ bound'] = (self._test_sk, (tcp, localhost, 1337), True)
        t['RedirectAllTraffic disabled localhost @ unbound'] = (self._test_sk, (tcp, localhost, 9999), False)

        return self._testGeneric(config, t)

    def testBlacklistProcess(self):
        config = self.makeConfig()
        config.blacklistProcess(self.settings.pythonname)

        arbitrary = self.settings.arbitrary

        tcp = socket.SOCK_STREAM
        udp = socket.SOCK_DGRAM

        t = OrderedDict() # The tests

        t['Global blacklisted process test'] = (self._test_sk, (tcp, arbitrary, 9999), False)

        return self._testGeneric(config, t)

    def testWhitelistProcess(self):
        config = self.makeConfig()
        config.whitelistProcess(self.settings.pythonname)

        arbitrary = self.settings.arbitrary

        tcp = socket.SOCK_STREAM
        udp = socket.SOCK_DGRAM

        t = OrderedDict() # The tests

        t['Global whitelisted process test'] = (self._test_sk, (tcp, arbitrary, 9999), True)

        return self._testGeneric(config, t)

    def testGeneral(self):
        config = self.makeConfig()

        domain_dne = self.settings.domain_dne
        ext_ip = self.settings.ext_ip
        arbitrary = self.settings.arbitrary
        blacklistedhost = self.settings.blacklistedhost
        blacklistedtcp = self.settings.blacklistedtcp
        blacklistedudp = self.settings.blacklistedudp
        localhost = self.settings.localhost
        dns_expected = self.settings.dns_expected

        tcp = socket.SOCK_STREAM
        udp = socket.SOCK_DGRAM

        t = OrderedDict() # The tests

        t['TCP local external IP @ bound'] = (self._test_sk, (tcp, ext_ip, 1337), True)
        t['TCP local external IP @ unbound'] = (self._test_sk, (tcp, ext_ip, 9999), True)
        t['TCP arbitrary @ bound'] = (self._test_sk, (tcp, arbitrary, 1337), True)
        t['TCP arbitrary @ unbound'] = (self._test_sk, (tcp, arbitrary, 9999), True)
        t['TCP domainname @ bound'] = (self._test_sk, (tcp, domain_dne, 1337), True)
        t['TCP domainname @ unbound'] = (self._test_sk, (tcp, domain_dne, 9999), True)
        t['TCP localhost @ bound'] = (self._test_sk, (tcp, localhost, 1337), True)
        # t['TCP localhost @ unbound'] = (self._test_sk, (tcp, localhost, 9999), False)

        t['UDP local external IP @ bound'] = (self._test_sk, (udp, ext_ip, 1337), True)
        t['UDP local external IP @ unbound'] = (self._test_sk, (udp, ext_ip, 9999), True)
        t['UDP arbitrary @ bound'] = (self._test_sk, (udp, arbitrary, 1337), True)
        t['UDP arbitrary @ unbound'] = (self._test_sk, (udp, arbitrary, 9999), True)
        t['UDP domainname @ bound'] = (self._test_sk, (udp, domain_dne, 1337), True)
        t['UDP domainname @ unbound'] = (self._test_sk, (udp, domain_dne, 9999), True)
        t['UDP localhost @ bound'] = (self._test_sk, (udp, localhost, 1337), True)
        # t['UDP localhost @ unbound'] = (self._test_sk, (udp, localhost, 9999), False)

        t['ICMP local external IP'] = (self._test_icmp, (ext_ip,), True)
        t['ICMP arbitrary host'] = (self._test_icmp, (arbitrary,), True)
        # t['ICMP domainname'] = (self._test_icmp, (domain_dne,), True)

        t['DNS listener test'] = (self._test_ns, (domain_dne, dns_expected), True)
        t['HTTP listener test'] = (self._test_http, (arbitrary,), True)
        t['FTP listener test'] = (self._test_ftp, (arbitrary,), True)

        t['Proxy listener HTTP test'] = (self._test_http, (arbitrary, 10), True)

        t['TCP blacklisted host @ unbound'] = (self._test_sk, (tcp, blacklistedhost, 9999), False)
        t['TCP arbitrary @ blacklisted unbound'] = (self._test_sk, (tcp, arbitrary, blacklistedtcp), False)
        t['UDP arbitrary @ blacklisted unbound'] = (self._test_sk, (udp, arbitrary, blacklistedudp), False)

        t['Listener process blacklist'] = (self._test_http, (arbitrary, self.settings.listener_proc_black), False)
        t['Listener process whitelist'] = (self._test_http, (arbitrary, self.settings.listener_proc_white), True)
        t['Listener host blacklist'] = (self._test_http, (arbitrary, self.settings.listener_host_black), True)
        t['Listener host whitelist'] = (self._test_http, (arbitrary, self.settings.listener_host_black), True)

        return self._testGeneric(config, t)

    def makeConfig(self, singlehostmode=True, proxied=True, redirectall=True):
        template = self.settings.configtemplate
        return FakeNetConfig(template, singlehostmode, proxied, redirectall)

    def writeConfig(self, config):
        logger.info('Writing config to %s' % (self.settings.configpath))
        config.write(self.settings.configpath)

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

    def __init__(self, startingpath):
        self.startingpath = startingpath
        self.configtemplate = os.path.join(startingpath, 'template.ini')

        # Where am I? Who are you?
        self.platform_name = platform.system()
        self.windows = (self.platform_name == 'Windows')
        self.linux = (self.platform_name.lower().startswith('linux'))

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
        self.listener_proc_black = 8080 # HTTP listener with process blacklist
        self.listener_proc_white = 8081 # HTTP listener with process whitelists
        self.listener_host_black = 8082 # HTTP listener with host blacklist
        self.listener_host_white = 8083 # HTTP listener with host whitelists
        self.localhost = '127.0.0.1'
        self.dns_expected = '192.0.2.123'
        self.domain_dne = 'does-not-exist-amirite.fireeye.com'

        # Behaviors
        self.sleep_after_start = 4
        self.sleep_before_stop = 1

    def genPath(self, winpath, unixypath):
        if self.windows:
            return os.path.expandvars(winpath)
        else:
            return os.path.expandvars(unixypath)

    def genFakenetCmd(self):
        return ('%s -f %s -l %s -c %s' %
                (self.fakenet, self.stopflag, self.logpath, self.configpath))

def main():
    if not is_admin():
        logger.info('Not an admin, exiting...')
        sys.exit(1)

    startingpath = os.getcwd()
    settings = FakeNetTestSettings(startingpath)
    tester = FakeNetTester(settings)

    logger.info('Running with privileges on %s' % (settings.platform_name))

    tester.doTests()

if __name__ == '__main__':
    main()
