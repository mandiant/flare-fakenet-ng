import os
import re
import glob
import socket
import struct
import logging
import binascii
import threading
import subprocess
import netfilterqueue
from debuglevels import *
from collections import defaultdict
from . import diverterbase


class IptCmdTemplateBase(object):
    """For managing insertion and removal of iptables rules.

    Construct and execute iptables command lines to add (-I or -A) and remove
    (-D) rules in the abstract. Base only handles iptables -I/-D and -i/-o args
    """

    def __init(self):
        self._addcmd = None
        self._remcmd = None

    def _iptables_format(self, chain, iface, argfmt):
        """Format iptables command line with optional interface restriction.

        Parameters
        ----------
        chain : string
            One of 'OUTPUT', 'POSTROUTING', 'INPUT', or 'PREROUTING', used for
            deciding the correct flag (-i versus -o)
        iface : string or NoneType
            Name of interface to restrict the rule to (e.g. 'eth0'), or None
        argfmt : string
            Format string for remaining iptables arguments. This format string
            will not be included in format string evaluation but is appended
            as-is to the iptables command.
        """
        flag_iface = ''
        if iface:
            if chain in ['OUTPUT', 'POSTROUTING']:
                flag_iface = '-o'
            elif chain in ['INPUT', 'PREROUTING']:
                flag_iface = '-i'
            else:
                raise NotImplementedError('Unanticipated chain %s' % (chain))

        self._addcmd = 'iptables -I {chain} {flag_if} {iface} {fmt}'
        self._addcmd = self._addcmd.format(chain=chain, flag_if=flag_iface,
                                           iface=(iface or ''), fmt=argfmt)
        self._remcmd = 'iptables -D {chain} {flag_if} {iface} {fmt}'
        self._remcmd = self._remcmd.format(chain=chain, flag_if=flag_iface,
                                           iface=(iface or ''), fmt=argfmt)

    def add(self):
        if not self._addcmd:
            raise ValueError('Iptables rule addition command not initialized')
        return subprocess.call(self._addcmd.split())

    def remove(self):
        if not self._remcmd:
            raise ValueError('Iptables rule removal command not initialized')
        return subprocess.call(self._remcmd.split())


class IptCmdTemplateNfq(IptCmdTemplateBase):
    """For constructing and executing NFQUEUE iptables rules"""
    def __init__(self, chain, qno, table, iface=None):
        fmt = '-t {} -j NFQUEUE --queue-num {}'.format(table, qno)
        self._iptables_format(chain, iface, fmt)


class IptCmdTemplateRedir(IptCmdTemplateBase):
    """For constructing and executing REDIRECT iptables rules"""
    def __init__(self, iface=None):
        fmt = '-t nat -j REDIRECT'
        self._iptables_format('PREROUTING', iface, fmt)


class IptCmdTemplateIcmpRedir(IptCmdTemplateBase):
    """For constructing and executing ICMP REDIRECT iptables rules"""
    def __init__(self, iface=None):
        fmt = '-t nat -p icmp -j REDIRECT'
        self._iptables_format('OUTPUT', iface, fmt)


class LinuxDiverterNfqueue(object):
    """NetfilterQueue object wrapper.

    Handles iptables rule addition/removal, NetfilterQueue management,
    netlink socket timeout setup, threading, and monitoring for asynchronous
    stop requests.

    Has a NetfilterQueue instance rather than sub-classing it, because it
    encapsulates a thread and other fields, and does not need to modify any
    methods of the NetfilterQueue object.

    The results are undefined if start() or stop() are called multiple times.
    """

    def __init__(self, qno, chain, table, callback, iface=None):
        self.logger = logging.getLogger('Diverter')

        # Specifications
        self.qno = qno
        self.chain = chain
        self.table = table
        self._rule = IptCmdTemplateNfq(self.chain, self.qno, self.table, iface)
        self._callback = callback
        self._nfqueue = netfilterqueue.NetfilterQueue()
        self._sk = None
        self._stopflag = False
        self._thread = None

        # State
        self._rule_added = False
        self._bound = False
        self._started = False

    def __repr__(self):
        return '%s/%s@%d' % (self.chain, self.table, self.qno)

    def start(self, timeout_sec=0.5):
        """Binds to the netfilter queue number specified in the ctor, obtains
        the netlink socket, sets a timeout of <timeout_sec>, and starts the
        thread procedure which checks _stopflag every time the netlink socket
        times out.
        """

        # Execute iptables to add the rule
        ret = self._rule.add()
        if ret != 0:
            return False

        self._rule_added = True

        # Bind the specified callback to the specified queue
        try:
            self._nfqueue.bind(self.qno, self._callback)
            self._bound = True
        except OSError as e:
            self.logger.error('Failed to start queue for %s: %s' %
                              (str(self), e.message))
        except RuntimeWarning as e:
            self.logger.error('Failed to start queue for %s: %s' %
                              (str(self), e.message))

        if not self._bound:
            return False

        # Facilitate _stopflag monitoring and thread joining
        self._sk = socket.fromfd(
            self._nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        self._sk.settimeout(timeout_sec)

        # Start a thread to run the queue and monitor the stop flag
        self._thread = threading.Thread(target=self._threadproc)
        self._thread.daemon = True
        self._stopflag = False
        try:
            self._thread.start()
            self._started = True
        except RuntimeError as e:
            self.logger.error('Failed to start queue thread: %s' % (e.message))

        return self._started

    def _threadproc(self):
        while not self._stopflag:
            try:
                self._nfqueue.run_socket(self._sk)
            except socket.timeout:
                # Ignore timeouts generated every N seconds due to the prior
                # call to settimeout(), and move on to re-evaluating the
                # current state of the stop flag.
                pass

    def stop_nonblocking(self):
        """Call this on each LinuxDiverterNfqueue object in turn to stop them
        all as close as possible to the same time rather than waiting for each
        one to time out and stop before moving on to the next.

        Perfect synchrony is a non-goal because halting the Diverter could
        disrupt existing connections anyway. Hence, it is up to the user to
        halt FakeNet-NG after any critical network operations have concluded.
        """
        self._stopflag = True

    def stop(self):
        self.stop_nonblocking()  # Ensure somebody has set the stop flag

        if self._started:
            self._thread.join()  # Wait for the netlink socket to time out

        if self._bound:
            self._nfqueue.unbind()

        if self._rule_added:
            self._rule.remove()  # Shell out to iptables to remove the rule


class ProcfsReader(object):
    """Standard row/field reading for proc files."""
    def __init__(self, path, skip, cb):
        self.path = path
        self.skip = skip
        self.cb = cb

    def parse(self, multi=False, max_col=None):
        """Rip through the file and call cb to extract field(s).

        Specify multi if you want to collect an aray instead of exiting the
        first time the callback returns anything.

        Only specify max_col if you are uncertain that the maximum column
        number you will access may exist. For procfs files, this should remain
        None.
        """
        retval = list() if multi else None

        try:
            with open(self.path, 'r') as f:
                while True:
                    line = f.readline()

                    # EOF case
                    if not len(line):
                        break

                    # Insufficient columns => ValueError
                    if max_col and (len(line) < max_col):
                        raise ValueError(('Line %d in %s has less than %d '
                                          'columns') %
                                         (n, self.path, max_col))
                    # Skip header lines
                    if self.skip:
                        self.skip -= 1
                        continue

                    cb_retval = self.cb(line.split())

                    if cb_retval:
                        if multi:
                            retval.append(cb_retval)
                        else:
                            retval = cb_retval
                            break
        except IOError as e:
            self.logger.error('Failed accessing %s: %s' % (path, e.message))
            # All or nothing
            retval = [] if multi else None

        return retval


class LinUtilMixin(diverterbase.DiverterPerOSDelegate):
    """Automate addition/removal of iptables rules, checking interface names,
    checking available netfilter queue numbers, etc.
    """

    def init_linux_mixin(self):
        self.old_dns = None
        self.iptables_captured = ''

    def getNewDestinationIp(self, ip):
        """On Linux, FTP tests fail if IP redirection uses the external IP, so
        always return localhost.
        """
        return '127.0.0.1'

    def check_active_ethernet_adapters(self):
        return (len(self._linux_get_ifaces()) > 0)

    def check_gateways(self):
        return True if self.linux_get_default_gw() else False

    def check_dns_servers(self):
        # TODO: Implement
        return True

    def check_ipaddresses(self):
        # TODO: Implement
        return True

    def fix_gateway(self):
        # TODO: Implement
        return False

    def fix_dns(self):
        # TODO: Implement
        return False

    def linux_capture_iptables(self):
        self.iptables_captured = ''
        ret = None

        try:
            p = subprocess.Popen(['iptables-save'], stdout=subprocess.PIPE)
            while True:
                buf = p.stdout.read()
                if buf == '':
                    break
                self.iptables_captured += buf

            if self.iptables_captured == '':
                self.logger.warning('Null iptables-save output, likely not ' +
                                    'privileged')
            ret = p.wait()
        except OSError as e:
            self.logger.error('Error executing iptables-save: %s' %
                              (e.message))

        return ret

    def linux_restore_iptables(self):
        ret = None

        self.pdebug(DIPTBLS, 'Restoring iptables')

        try:
            p = subprocess.Popen(['iptables-restore'], stdin=subprocess.PIPE)
            p.communicate(self.iptables_captured)
            ret = p.wait()
        except OSError as e:
            self.logger.error('Error executing iptables-restore: %s' %
                              (e.message))

        return ret

    def linux_flush_iptables(self):
        rets = []
        cmd = ''

        table_names = ['raw', 'filter', 'mangle', 'nat']

        self.pdebug(DIPTBLS, 'Flushing iptables: %s' %
                    (', '.join(table_names)))

        try:
            for table_name in table_names:
                cmd = 'iptables --flush -t %s' % (table_name)
                p = subprocess.Popen(cmd.split())
                ret = p.wait()
                rets.append(ret)
                if ret != 0:
                    self.logger.error('Received return code %d from %s' +
                                      (ret, cmd))
        except OSError as e:
            self.logger.error('Error executing %s: %s' % (cmd, e.message))

        return rets

    def linux_get_current_nfnlq_bindings(self):
        """Determine what NFQUEUE queue numbers (if any) are already bound by
        existing libnfqueue client processes.

        Although iptables rules may exist specifying other queues in addition
        to these, the netfilter team does not support using libiptc (such as
        via python-iptables) to detect that condition, so code that does so may
        break in the future. Shelling out to iptables and parsing its output
        for NFQUEUE numbers is not an attractive option. The practice of
        checking the currently bound NetFilter netlink queue bindings is a
        compromise. Note that if an iptables rule specifies an NFQUEUE number
        that is not yet bound by any process in the system, the results are
        undefined. We can add FakeNet arguments to be passed to the Diverter
        for giving the user more control if it becomes necessary.
        """

        procfs_path = '/proc/net/netfilter/nfnetlink_queue'

        qnos = list()
        try:
            with open(procfs_path, 'r') as f:
                lines = f.read().split('\n')
                for line in lines:
                    line = line.strip()
                    if line:
                        queue_nr = int(line.split()[0], 10)
                        self.pdebug(DNFQUEUE, ('Found NFQUEUE #' +
                                    str(queue_nr) + ' per ') + procfs_path)
                        qnos.append(queue_nr)
        except IOError as e:
            self.logger.debug(('Failed to open %s to enumerate netfilter '
                               'netlink queues, caller may proceed as if '
                               'none are in use: %s') %
                              (procfs_path, e.message))

        return qnos

    def linux_get_next_nfqueue_numbers(self, n):
        # Queue numbers are of type u_int16_t hence 0xffff being the maximum
        QNO_MAX = 0xffff

        existing_queues = self.linux_get_current_nfnlq_bindings()

        next_qnos = list()
        for qno in xrange(QNO_MAX + 1):
            if qno not in existing_queues:
                next_qnos.append(qno)
                if len(next_qnos) == n:
                    break

        return next_qnos

    def linux_iptables_redir_iface(self, iface):
        """Linux-specific iptables processing for interface-based redirect
        rules.

        returns:
            tuple(bool, list(IptCmdTemplate))
            Status of the operation and any successful iptables rules that will
            need to be undone.
        """

        iptables_rules = []
        rule = IptCmdTemplateRedir(iface)
        ret = rule.add()

        if ret != 0:
            self.logger.error('Failed to create PREROUTING/REDIRECT ' +
                              'rule for %s, stopping...' % (iface))
            return (False, iptables_rules)

        iptables_rules.append(rule)

        return (True, iptables_rules)

    def _linux_get_ifaces(self):
        ifaces = []

        procfs_path = '/proc/net/dev'

        try:
            with open(procfs_path, 'r') as f:
                lines = f.read().split('\n')
                for line in lines:
                    # Only lines with colons contain interface names
                    if ':' in line:
                        fields = line.split(':')
                        ifaces.append(fields[0].strip())
        except IOError as e:
            self.logger.error('Failed to open %s to enumerate interfaces: %s' %
                              (procfs_path, e.message))

        return ifaces

    def linux_remove_iptables_rules(self, rules):
        """Execute the iptables command to remove each rule that was
        successfully added.
        """
        failed = []

        for rule in rules:
            ret = rule.remove()
            if ret != 0:
                failed.append(rule)

        return failed

    def linux_modifylocaldns_ephemeral(self):
        resolvconf_path = '/etc/resolv.conf'
        self.old_dns = None

        try:
            with open(resolvconf_path, 'r') as f:
                self.old_dns = f.read()
        except IOError as e:
            self.logger.error(('Failed to open %s to save DNS ' +
                              'configuration: %s') % (resolvconf_path,
                              e.message))

        if self.old_dns:
            try:
                with open(resolvconf_path, 'w') as f:
                    ip = self.linux_first_nonlo_ip()
                    if not ip:
                        ip = '127.0.0.1'
                    f.write('nameserver %s\n' % (ip))
            except IOError as e:
                self.logger.error(('Failed to open %s to modify DNS ' +
                                  'configuration: %s') % (resolvconf_path,
                                  e.message))

    def linux_restore_local_dns(self):
        resolvconf_path = '/etc/resolv.conf'
        if self.old_dns:
            try:
                with open(resolvconf_path, 'w') as f:
                    f.write(self.old_dns)
                    self.old_dns = None
            except IOError as e:
                self.logger.error(('Failed to open %s to restore DNS ' +
                                  'configuration: %s') % (resolvconf_path,
                                  e.message))

    def linux_find_processes(self, names):
        """But what if a blacklisted process spawns after we call
        this? We'd have to call this every time we do anything.
        """
        pids = []

        proc_pid_dirs = glob.glob('/proc/[0-9]*/')
        comm_file = ''

        for proc_pid_dir in proc_pid_dirs:
            comm_file = os.path.join(proc_pid_dir, 'comm')
            try:
                with open(comm_file, 'r') as f:
                    comm = f.read().strip()
                    if comm in names:
                        pid = int(proc_pid_dir.split('/')[-2], 10)
                        pids.append(pid)
            except IOError as e:
                # Silently ignore
                pass

        return pids

    def _port_for_proc_net_tcp(self, port):
        return ':%s' % (hex(port).lstrip('0x').zfill(4).upper())

    def _ip_port_for_proc_net_tcp(self, ipver, ip_dotdecimal, port):
        # IPv6 untested
        af = socket.AF_INET6 if ipver == 6 else socket.AF_INET
        ip_pton = socket.inet_pton(af, ip_dotdecimal)

        ip_str = binascii.hexlify(ip_pton[::-1]).upper()
        port_str = self._port_for_proc_net_tcp(port)

        return '%s:%s' % (ip_str, port_str)

    def linux_find_sock_by_endpoint(self, ipver, proto_name, ip, port,
                                    local=True):
        """Check args and call _linux_find_sock_by_endpoint_unsafe."""

        if proto_name and ip and port:
            return self._linux_find_sock_by_endpoint_unsafe(ipver, proto_name,
                                                            ip, port, local)
        else:
            return None

    def _linux_find_sock_by_endpoint_unsafe(self, ipver, proto_name, ip, port,
                                            local=True):
        """Search /proc/net/tcp for a socket whose local (field 1, zero-based)
        or remote (field 2) address matches ip:port and return the
        corresponding inode (field 9).

        Fields referenced above are zero-based.

        Example contents of /proc/net/tcp (wrapped and double-spaced)

          sl  local_address rem_address   st tx_queue rx_queue tr tm->when
            retrnsmt   uid  timeout inode

           0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000
            00000000     0        0 53320 1 0000000000000000 100 0 0 10 0

           1: 00000000:021A 00000000:0000 0A 00000000:00000000 00:00000000
            00000000     0        0 11125 1 0000000000000000 100 0 0 10 0

           2: 00000000:1A0B 00000000:0000 0A 00000000:00000000 00:00000000
            00000000    39        0 11175 1 0000000000000000 100 0 0 10 0

           3: 0100007F:8071 0100007F:1F90 01 00000000:00000000 00:00000000
            00000000  1000        0 58661 1 0000000000000000 20 0 0 10 -1

           4: 0100007F:1F90 0100007F:8071 01 00000000:00000000 00:00000000
            00000000  1000        0 58640 1 0000000000000000 20 4 30 10 -1

        Returns inode
        """
        INODE_COLUMN = 9

        # IPv6 untested
        suffix = '6' if (ipver == 6) else ''

        procfs_path = '/proc/net/' + proto_name.lower() + suffix

        inode = None

        port_tag = self._port_for_proc_net_tcp(port)

        match_column = 1 if local else 2
        local_column = 1
        remote_column = 2

        try:
            with open(procfs_path) as f:
                f.readline()  # Discard header
                while True:
                    line = f.readline()
                    if not len(line):
                        break

                    fields = line.split()

                    # Local matches can be made based on port only
                    if local and fields[local_column].endswith(port_tag):
                        inode = int(fields[INODE_COLUMN], 10)
                        self.pdebug(DPROCFS, 'MATCHING CONNECTION: %s' %
                                    (line.strip()))
                        break
                    # Untested: Remote matches must be more specific and
                    # include the IP address. Hence, an "endpoint tag" is
                    # constructed to match what would appear in
                    # /proc/net/{tcp,udp}{,6}
                    elif not local:
                        endpoint_tag = self._ip_port_for_proc_net_tcp(ipver,
                                                                      ip, port)
                        if fields[remote_column] == endpoint_tag:
                            inode = int(fields[INODE_COLUMN], 10)
                            self.pdebug(DPROCFS, 'MATCHING CONNECTION: %s' %
                                        (line.strip()))
        except IOError as e:
            self.logger.error('No such protocol/IP ver (%s) or error: %s' %
                              (procfs_path, e.message))

        return inode

    def linux_get_default_gw(self):
        DEST_COLUMN = 1
        GW_COLUMN = 2
        MASK_COLUMN = 7

        dgw = None

        def scan_for_default_gw(fields):
            if fields[DEST_COLUMN] == '00000000':
                s = fields[GW_COLUMN]
                return socket.inet_ntoa(binascii.unhexlify(s)[::-1])

        r = ProcfsReader('/proc/net/route', 1, scan_for_default_gw)
        dgw = r.parse()

        return dgw

    def linux_redir_icmp(self, iface=None):
        rule = IptCmdTemplateIcmpRedir(iface)
        ret = rule.add()
        return (ret == 0), rule

    def linux_first_nonlo_ip(self):
        for ip in self.ip_addrs[4]:
            if not ip.startswith('127.'):
                return ip
        return None

    def linux_set_default_gw(self, ip=None):
        ip = self.linux_first_nonlo_ip()
        if not ip:
            return False

        cmd = 'route add default gw %s' % (ip)
        ret = subprocess.call(cmd.split())
        return ret == 0

    def linux_find_process_connections(self, names, inode_sought=None):
        inodes = list()

        for pid in self.linux_find_processes(names):

            # Check all /proc/<pid>/fd/* to see if they are symlinks
            proc_fds_glob = '/proc/%d/fd/*' % (pid)
            proc_fd_paths = glob.glob(proc_fds_glob)
            for fd_path in proc_fd_paths:
                inode = self._linux_get_sk_ino_for_fd_file(fd_path)
                if inode:
                    if inode_sought is None:
                        inodes.append(inode)
                    elif inode == inode_sought:
                        self.pdebug(DPROCFS, 'MATCHING FD %s -> socket:[%d]' %
                                    (fd_path, inode))
                        return [inode]

        return inodes

    def _linux_get_sk_ino_for_fd_file(self, fd_file_path):
        inode = None

        try:
            target = os.readlink(fd_file_path)
            m = re.match(r'socket:\[([0-9]+)\]', target)
            if m:
                inode = int(m.group(1), 10)
        except OSError:
            pass

        return inode

    def linux_get_comm_by_pid(self, pid):
        comm = None

        procfs_path = '/proc/%d/comm' % (pid)
        try:
            with open(procfs_path, 'r') as f:
                comm = f.read().strip()
        except IOError as e:
            self.pdebug(DPROCFS, 'Failed to open %s: %s' %
                        (procfs_path, e.message))
        return comm

    def linux_get_pid_comm_by_endpoint(self, ipver, proto_name, ip, port):
        """Obtain a pid and executable name associated with an endpoint.

        NOTE: procfs does not allow us to answer questions like "who just
        called send()?"; only questions like "who owns a socket associated with
        this local port?" Since fork() etc. can result in multiple ownership,
        the real answer may be that multiple processes actually own the socket.
        This implementation stops at the first match and hence may not give a
        perfectly accurate answer in those cases. In practice, this may be
        adequate, or it may need to be revisited to return a list of (pid,comm)
        tuples to take into account cases where multiple processes have the
        same inode open.
        """
        pid, comm = None, None

        # 1. Find the inode number associated with this socket
        inode = self.linux_find_sock_by_endpoint(ipver, proto_name, ip, port)

        if inode:
            # 2. Search for a /proc/<pid>/fd/<fd> that has this inode open.
            proc_fds_glob = '/proc/[0-9]*/fd/*'
            proc_fd_paths = glob.glob(proc_fds_glob)
            for fd_path in proc_fd_paths:
                candidate = self._linux_get_sk_ino_for_fd_file(fd_path)
                if candidate and (candidate == inode):

                    # 3. Record the pid and executable name
                    try:
                        pid = int(fd_path.split('/')[-3], 10)
                        comm = self.linux_get_comm_by_pid(pid)
                    # Not interested in e.g.
                    except ValueError:
                        pass

        return pid, comm

    def get_pid_comm(self, pkt):
        return self.linux_get_pid_comm_by_endpoint(pkt.ipver, pkt.proto,
                                                   pkt.src_ip, pkt.sport)

    def linux_endpoint_owned_by_processes(self, ipver, proto_name, ip, port,
                                          names):
        inode = self.linux_find_sock_by_endpoint(ipver, proto_name, ip, port)
        t = self._ip_port_for_proc_net_tcp(ipver, ip, port)

        if inode:
            self.pdebug(DPROCFS, 'inode %d found for %s:%s (%s)' %
                        (inode, ip, port, t))
            conns = self.linux_find_process_connections(names, inode)
            if len(conns):
                self.pdebug(DPROCFS, 'FOUND inode %d for %s' %
                            (inode, str(names)))
                return True
        else:
            self.pdebug(DPROCFS, 'No inode found for %s:%d (%s)' %
                        (ip, port, t))

        return False
