import logging
import dpkt
import subprocess
import binascii
import socket
import glob
import os
import re
import struct
import threading
import netfilterqueue
from diverters import utils

# Debug print levels for fine-grained debug trace output control
DNFQUEUE = (1 << 0)     # netfilterqueue
DGENPKT = (1 << 1)      # Generic packet handling
DGENPKTV = (1 << 2)     # Generic packet handling with TCP analysis
DCB = (1 << 3)          # Packet handlign callbacks
DPROCFS = (1 << 4)      # procfs
DIPTBLS = (1 << 5)      # iptables
DNONLOC = (1 << 6)      # Nonlocal-destined datagrams
DDPF = (1 << 7)         # DPF (Dynamic Port Forwarding)
DDPFV = (1 << 8)         # DPF (Dynamic Port Forwarding) Verbose
DIPNAT = (1 << 9)       # IP redirection for nonlocal-destined datagrams
DIGN = (1 << 10)         # Packet redirect ignore conditions
DFTP = (1 << 11)         # FTP checks
DMISC = (1 << 27)       # Miscellaneous

DCOMP = 0x0fffffff      # Component mask
DFLAG = 0xf0000000      # Flag mask
DEVERY = 0x0fffffff     # Log everything, low verbosity
DEVERY2 = 0x8fffffff    # Log everything, complete verbosity

DLABELS = {
    DNFQUEUE: 'NFQUEUE',
    DGENPKT: 'GENPKT',
    DGENPKTV: 'GENPKTV',
    DPROCFS: 'PROCFS',
    DIPTBLS: 'IPTABLES',
    DNONLOC: 'NONLOC',
    DDPF: 'DPF',
    DDPFV: 'DPFV',
    DIPNAT: 'IPNAT',
    DIGN: 'IGN',
    DIGN | DFTP: 'IGN-FTP',
    DMISC: 'MISC',
}

DLABELS_INV = {v.upper(): k for k, v in DLABELS.iteritems()}


class IptCmdTemplate:
    """For managing insertion and removal of iptables rules.

    Construct and execute iptables command lines to add (-I or -A) and remove
    (-D) rules.

    The removal half of this is now redundant with
    LinUtilMixin.linux_{capture,restore}_iptables().
    """

    def __init__(self, fmt, args=[], add='-I', rem='-D', add_idx=0, rem_idx=0):
        self._addcmd = fmt % tuple(args[0:add_idx] + [add] + args[add_idx:])
        self._remcmd = fmt % tuple(args[0:add_idx] + [rem] + args[rem_idx:])

    def gen_add_cmd(self): return self._addcmd

    def gen_remove_cmd(self): return self._remcmd

    def add(self): return subprocess.call(self._addcmd.split())

    def remove(self): return subprocess.call(self._remcmd.split())


class ProcfsReader:
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
                        raise ValueError('Line %d in %s has less than %d columns' %
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


def capture_iptables(logger=None):
    '''
    Capture current iptables rules
    @param OPTIONAL logger: a logger to use, or None to use default logger
    @return iptables rules on success, None on error
    '''
    logger = logger if logger is not None else logging.getLogger()

    iptables_captured = ''
    try:
        p = subprocess.Popen(['iptables-save'], stdout=subprocess.PIPE)
        while True:
            buf = p.stdout.read()
            if buf == '':
                break
            iptables_captured += buf

        if iptables_captured == '':
            logger.error('Null iptables-save output, likely not privileged')
        if not p.wait() == 0:
            return None
    except OSError as e:
        logger.error('Error executing iptables-save: %s' % (e.message,))
        return None

    return iptables_captured


def restore_iptables(iptables_captured, logger=None):
    '''
    Restore iptables rules.
    @param OPTIONAL logger: a logger to use, or None to use default logger
    @return True on success, False on error
    '''
    logger = logger if logger is not None else logging.getLogger()

    error = False
    try:
        p = subprocess.Popen(['iptables-restore'], stdin=subprocess.PIPE)
        p.communicate(iptables_captured)
        if not p.wait() == 0:
            error = True

    except OSError as e:
        logger.error('Error executing iptables-restore: %s' % (e.message,))
        error = True
    return not error

def flush_iptables(logger=None):
    '''
    Flush iptables rulse
    @param OPTIONAL logger: a logger to use, or None to use default logger
    @return True on success, False if any error occurs
    '''
    logger = logger if logger is not None else logging.getLogger()
    error = False
    cmd = ''
    table_names = ['raw', 'filter', 'mangle', 'nat']

    logger.debug(DIPTBLS, 'Flushing iptables: %s' % (', '.join(table_names)))

    try:
        for table_name in table_names:
            cmd = 'iptables --flush -t %s' % (table_name)
            p = subprocess.Popen(cmd.split())
            ret = p.wait()
            if ret != 0:
                logger.error('Received return code %d from %s' % (ret, cmd))
                error = True
    except OSError as e:
        logger.error('Error executing %s: %s' % (cmd, e.message))
        error = True

    return not error

def get_current_nfnlq_bindings(logger=None):
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

    @param OPTIONAL logger: a logger to use, or None to use default logger
    @return array of queue numbers on success, None on error
    """

    logger = logger if logger is not None else logging.getLogger()

    procfs_path = '/proc/net/netfilter/nfnetlink_queue'

    qnos = list()
    try:
        with open(procfs_path, 'r') as f:
            lines = f.read().split('\n')
            for line in lines:
                line = line.strip()
                if line:
                    queue_nr = int(line.split()[0], 10)
                    
                    logger.debug(DNFQUEUE, ('Found NFQUEUE #' +
                                str(queue_nr) + ' per ') + procfs_path)
                    qnos.append(queue_nr)
    except IOError as e:
        logger.error(('Failed to open %s to enumerate netfilter ' +
                      'netlink queues, caller may proceed as if ' +
                      'none are in use: %s') % (procfs_path, e.message))
        return None
    return qnos

def get_next_nfqueue_numbers(n, logger=None):

    logger = logger if logger is not None else logging.getLogger()
    # Queue numbers are of type u_int16_t hence 0xffff being the maximum
    QNO_MAX = 0xffff

    existing_queues = get_current_nfnlq_bindings(logger)
    if existing_queues is None:
        return []

    next_qnos = list()
    for qno in xrange(QNO_MAX + 1):
        if qno not in existing_queues:
            next_qnos.append(qno)
            if len(next_qnos) == n:
                break

    return next_qnos

def get_ifaces(logger=None):
    '''
    Get all interfaces
    @param OPTIONAL logger: a logger to use, or None to use default logger
    @return list of interfaces on successs, None if any error occurs
    '''
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
        logger.error('Failed to open %s to enumerate interfaces: %s' %
                          (procfs_path, e.message))
        return list()
    return ifaces



def iptables_redir_nonlocal(specified_ifaces, logger=None):
    """Linux-specific iptables processing for 'LinuxRedirectNonlocal'
    configuration item.

    @param specified_ifaces: interfaces
    @param OPTIONAL logger: a logger to use, or None to use default logger
    @returns:
        tuple(bool, list(IptCmdTemplate))
        Status of the operation and any successful iptables rules that will
        need to be undone.
    """

    logger = logger if logger is not None else logging.getLogger()

    local_ifaces = get_ifaces()
    all_iface_aliases = ['any', '*']
    acceptable_ifaces = local_ifaces + all_iface_aliases
    iptables_rules = []

    # Catch cases where the user isn't going to get what they expect
    # because iptables does not err for non-existent ifaces...
    if not set(specified_ifaces).issubset(acceptable_ifaces):
        # And indicate ALL interfaces that do not appear to exist
        for iface in specified_ifaces:
            if iface not in acceptable_ifaces:
                logger.error(('Interface %s not found for nonlocal ' +
                              'packet redirection, must be one of ' +
                              '%s') % (iface, str(acceptable_ifaces)))
        return (False, [])

    for iface in specified_ifaces:
        fmt, args = '', list()
        if iface in all_iface_aliases:
            # Handle */any case by omitting -i switch and corresponding arg
            fmt = 'iptables -t nat %s PREROUTING -j REDIRECT'
        else:
            fmt = 'iptables -t nat %s PREROUTING -i %s -j REDIRECT'
            args = [iface]

        rule = IptCmdTemplate(fmt, args)
        ret = rule.add()

        if ret != 0:
            logger.error('Failed to create PREROUTING/REDIRECT ' +
                         'rule for %s, stopping...' % (iface))
            return (False, iptables_rules)

        iptables_rules.append(rule)

    return (True, iptables_rules)

def remove_iptables_rules(rules, logger=None):
    """Execute the iptables command to remove each rule that was
    successfully added.
    """
    logger = logger if logger is not None else logging.getLogger()

    failed = []

    for rule in rules:
        ret = rule.remove()
        if ret != 0:
            failed.append(rule)

    return failed

def first_nonlo_ip(ip_addrs, logger=None):
    for ip in ip_addrs[4]:
        if not ip.startswith('127.'):
            return ip
    return None

def modifylocaldns_ephemeral(ip_addrs, logger=None):
    '''
    @return old DNS server entry on success, None on error
    '''

    logger = logger if logger is not None else logging.getLogger()
    resolvconf_path = '/etc/resolv.conf'
    old_dns = None

    try:
        with open(resolvconf_path, 'r') as f:
            old_dns = f.read()
    except IOError as e:
        logger.error(('Failed to open %s to save DNS ' +
                      'configuration: %s') % (resolvconf_path, e.message))
        return None

    if old_dns:
        try:
            with open(resolvconf_path, 'w') as f:
                ip = first_nonlo_ip(ip_addrs, logger)
                if not ip:
                    ip = '127.0.0.1'
                f.write('nameserver %s\n' % (ip))
        except IOError as e:
            logger.error(('Failed to open %s to modify DNS ' +
                          'configuration: %s') % (resolvconf_path, e.message))
            return None
    return old_dns


def restore_local_dns(old_dns, logger=None):
    logger = logger if logger is not None else logging.getLogger()
    resolvconf_path = '/etc/resolv.conf'
    if old_dns:
        try:
            with open(resolvconf_path, 'w') as f:
                f.write(old_dns)
        except IOError as e:
            logger.error(('Failed to open %s to restore DNS ' +
                          'configuration: %s') % (resolvconf_path, e.message))
    return True

def find_processes(names, logger=None):
    """Yeah great, but what if a blacklisted process spawns after we call
    this? We'd have to call this every time we do anything - expensive! Then
    again,
    """
    logger = logger if logger is not None else logging.getLogger()
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


def find_process_connections(names, inode_sought=None, logger=None):
    logger = logger if logger is not None else logging.getLogger()
    inodes = list()

    for pid in find_processes(names, logger):

        # Check all /proc/<pid>/fd/* to see if they are symlinks
        proc_fds_glob = '/proc/%d/fd/*' % (pid)
        proc_fd_paths = glob.glob(proc_fds_glob)
        for fd_path in proc_fd_paths:
            inode = _get_sk_ino_for_fd_file(fd_path)
            if inode:
                if inode_sought is None:
                    inodes.append(inode)
                elif inode == inode_sought:
                    logger.debug(DPROCFS, 'MATCHING FD %s -> socket:[%d]' %
                                (fd_path, inode))
                    return [inode]

    return inodes

def _get_sk_ino_for_fd_file(fd_file_path, logger=None):
    inode = None

    try:
        target = os.readlink(fd_file_path)
        m = re.match(r'socket:\[([0-9]+)\]', target)
        if m:
            inode = int(m.group(1), 10)
    except OSError:
        pass

    return inode

def _port_for_proc_net_tcp(port):
    return ':%s' % (hex(port).lstrip('0x').zfill(4).upper())

def _ip_port_for_proc_net_tcp(ipver, ip_dotdecimal, port):
    # IPv6 untested
    af = socket.AF_INET6 if ipver == 6 else socket.AF_INET
    ip_pton = socket.inet_pton(af, ip_dotdecimal)

    ip_str = binascii.hexlify(ip_pton[::-1]).upper()
    port_str = _port_for_proc_net_tcp(port)

    return '%s:%s' % (ip_str, port_str)

def find_sock_by_endpoint(ipver, proto_name, ip, port, local=True, logger=None):
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
    logger = logger if logger is not None else logging.getLogger()

    INODE_COLUMN = 9

    # IPv6 untested
    suffix = '6' if (ipver == 6) else ''

    procfs_path = '/proc/net/' + proto_name.lower() + suffix

    inode = None

    port_tag = _port_for_proc_net_tcp(port)

    match_column = 1 if local else 2
    local_column = 1
    remote_column = 2

    try:
        with open(procfs_path) as f:
            f.readline()  # Disard header
            while True:
                line = f.readline()
                if not len(line):
                    break

                fields = line.split()

                # Local matches can be made based on port only
                if local and fields[local_column].endswith(port_tag):
                    inode = int(fields[INODE_COLUMN], 10)
                    logger.debug(DPROCFS, 'MATCHING CONNECTION: %s' %
                                (line.strip()))
                    break
                # Untested: Remote matches must be more specific and
                # include the IP address. Hence, an "endpoint tag" is
                # constructed to match what would appear in
                # /proc/net/{tcp,udp}{,6}
                elif not local:
                    endpoint_tag = _ip_port_for_proc_net_tcp(ipver, ip, port)
                    if fields[remote_column] == endpoint_tag:
                        inode = int(fields[INODE_COLUMN], 10)
                        logger.debug(DPROCFS, 'MATCHING CONNECTION: %s' %
                                     (line.strip()))
    except IOError as e:
        logger.error('No such protocol/IP ver (%s) or error: %s' %
                      (procfs_path, e.message))

    return inode

def XXX_endpoint_owned_by_processes(ipver, proto_name, ip, port, names, logger=None):
    logger = logger if logger is not None else logging.getLogger()
    inode = find_sock_by_endpoint(ipver, proto_name, ip, port)
    t = _ip_port_for_proc_net_tcp(ipver, ip, port)

    if inode:
        logger.debug(DPROCFS, 'inode %d found for %s:%s (%s)' %
                     (inode, ip, port, t))
        conns = find_process_connections(names, inode)
        if len(conns):
            logger.debug(DPROCFS, 'FOUND inode %d for %s' %
                         (inode, str(names)))
            return True
    else:
        logger.debug(DPROCFS, 'No inode found for %s:%d (%s)' %
                     (ip, port, t))

    return False


def get_comm_by_pid(pid, logger=None):
    logger = logger if logger is not None else logging.getLogger()
    comm = None

    procfs_path = '/proc/%d/comm' % (pid)
    try:
        with open(procfs_path, 'r') as f:
            comm = f.read().strip()
    except IOError as e:
        logger.debug(DPROCFS, 'Failed to open %s: %s' %
                     (procfs_path, e.message))
    return comm


def get_procname_from_ip_packet(ip_packet):
    _pid, procname = get_pid_and_procname_from_ip_packet(ip_packet)
    return procname


def get_pid_and_procname_from_ip_packet(ip_packet):
    tport = utils.tport_from_ippacket(ip_packet)
    ipv = ip_packet.version
    src = ip_packet.src
    proto = tport.name
    sport = tport.sport
    
    return get_pid_comm_by_endpoint(ipv, proto, src, sport)
    

def get_pid_comm_by_endpoint(ipver, proto_name, ip, port, logger=None):
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
    logger = logger if logger is not None else logging.getLogger()
    pid, comm = None, None

    # 1. Find the inode number associated with this socket
    inode = find_sock_by_endpoint(ipver, proto_name, ip, port, logger=logger)

    if inode:
        # 2. Search for a /proc/<pid>/fd/<fd> that has this inode open.
        proc_fds_glob = '/proc/[0-9]*/fd/*'
        proc_fd_paths = glob.glob(proc_fds_glob)
        for fd_path in proc_fd_paths:
            candidate = _get_sk_ino_for_fd_file(fd_path, logger)
            if candidate and (candidate == inode):

                # 3. Record the pid and executable name
                try:
                    pid = int(fd_path.split('/')[-3], 10)
                    comm = get_comm_by_pid(pid, logger)
                # Not interested in e.g.
                except ValueError:
                    pass

    return pid, comm


def get_default_gw():
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

def check_gateways():
    return True if get_default_gw() else False


def set_default_gw(self, ip_addrs, ip=None):
    ip = first_nonlo_ip(ip_addrs)
    if not ip:
        return False

    cmd = 'route add default gw %s' % (ip)
    ret = subprocess.call(cmd.split())
    return ret == 0

def check_active_ethernet_adapters():
    return (len(get_ifaces()) > 0)

def check_dns_servers():
    return True

def redir_icmp():
    fmt = 'iptables -t nat %s OUTPUT -p icmp -j REDIRECT'
    rule = IptCmdTemplate(fmt)
    ret = rule.add()
    return (ret == 0), rule

def parse_nfqueue_packet(bytez):
    ipversion = utils.get_ip_version(bytez)
    if ipversion == 0x04:
        return parse_nfqueue_ipv4_packet(bytez)
    if ipversion == 0x06:
        return parse_nfqueue_ipv6_packet(bytez)
    return None, None

def parse_nfqueue_ipv4_packet(bytez):
    hdr = dpkt.ip.IP(bytez)
    if hdr.hl < 5:
        return None, None
    return hdr, hdr.p

def parse_nfqueue_ipv6_packet(bytez):
    hdr = dpkt.ip6.IP6(raw)
    if hdr.hl < 5:
        return None, None
    return hdr, hdr.p

