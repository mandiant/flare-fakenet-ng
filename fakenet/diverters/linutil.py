import socket
import logging
import threading
import subprocess
import netfilterqueue

class IptCmdTemplate:
    """For managing insertion and removal of iptables rules.

    Standardizes, centralizes, and de-duplicates code used frequently
    throughout the Linux Diverter to construct and execute iptables command
    lines to add (-I or -A) and remove (-D) rules.
    """

    def __init__(self, fmt, args=[], add='-I', rem='-D', add_idx=0, rem_idx=0):
        self._addcmd = fmt % tuple(args[0:add_idx] + [add] + args[add_idx:])
        self._remcmd = fmt % tuple(args[0:add_idx] + [rem] + args[rem_idx:])

    def gen_add_cmd(self): return self._addcmd
    def gen_remove_cmd(self): return self._remcmd
    def add(self): return subprocess.call(self._addcmd.split())
    def remove(self): return subprocess.call(self._remcmd.split())

class LinuxDiverterNfqueue:
    """NetfilterQueue object wrapper.
    
    Handles iptables rule addition/removal, NetfilterQueue management,
    netlink socket timeout setup, threading, and monitoring for asynchronous
    stop requests.

    Has a NetfilterQueue instance rather than sub-classing it, because it
    encapsulates a thread and other fields, and does not need to modify any
    methods of the NetfilterQueue object.

    The results are undefined if start() or stop() are called multiple times.
    """

    def __init__(self, qno, chain, table, callback):
        self.logger = logging.getLogger('Diverter')

        # e.g. iptables <-I> <INPUT> -t <mangle> -j NFQUEUE --queue-num <0>'
        fmt = 'iptables %s %s -t %s -j NFQUEUE --queue-num %d'

        # Specifications
        self.qno = qno
        self.chain = chain
        self.table = table
        self._rule = IptCmdTemplate(fmt, [self.chain, self.table, self.qno])
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
        self._sk = socket.fromfd(self._nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        self._sk.settimeout(timeout_sec)

        # Start a thread to run the queue and monitor the stop flag
        self._thread = threading.Thread(target=self._threadproc)
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

class LinUtilMixin():
    """Automate addition/removal of iptables rules, checking interface names,
    checking available netfilter queue numbers, etc.
    """

    def check_active_ethernet_adapters(self):
        return (len(self._linux_get_ifaces()) > 0)

    def check_gateways(self):
        # TODO: Implement
        return True

    def check_dns_servers(self):
        # TODO: Implement
        return True

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
                        self.logger.debug(('Found NFQUEUE #' + str(queue_nr) +
                                          ' per ') + procfs_path)
                        qnos.append(queue_nr)
        except IOError as e:
            self.logger.warning(('Failed to open %s to enumerate netfilter ' +
                    'netlink queues, caller may proceed as if none are in ' +
                    'use.') %
                    (procfs_path))

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

    def linux_redir_nonlocal(self, specified_ifaces):
        """Linux-specific iptables processing for 'LinuxRedirectNonlocal'
        configuration item.

        returns:
            tuple(bool, list(IptCmdTemplate))
            Status of the operation and any successful iptables rules that will
            need to be undone.
        """

        local_ifaces = self._linux_get_ifaces()
        iptables_rules = []

        # Catch cases where the user isn't going to get what they expect
        # because iptables does not err for non-existent ifaces...
        if not set(specified_ifaces).issubset(local_ifaces):
            # And indicate ALL interfaces that do not appear to exist
            for iface in specified_ifaces:
                if iface not in local_ifaces:
                    self.logger.error(('Interface %s not found for ' +
                            'nonlocal packet redirection') % (iface))
            return (False, [])

        for iface in specified_ifaces:
            rule = IptCmdTemplate(
                    'iptables -t nat %s PREROUTING -i %s -j REDIRECT', [iface])
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
            self.logger.error('Failed to open %s to enumerate interfaces' %
                    (procfs_path))

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
