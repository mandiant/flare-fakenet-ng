import socket
import threading
import netfilterqueue
from diverters.linux.utils import IptCmdTemplate
from diverters.linux import utils as lutils
from diverters.monitor import TrafficMonitor
from diverters import BaseObject
from diverters import utils
import logging


def make_nfqueue_monitor(qno, chain, table, callback, conditions, mangler):
    config = {
        'qno': qno, 'chain': chain, 'table': table,
        'callback': callback, 'conditions': conditions, 'mangler': mangler,
    }
    q = NfQueueMonitor(config)
    if not q.initialize():
        return None
    return q


class NfQueueMonitor(TrafficMonitor):
    """NetfilterQueue object wrapper.

    Handles iptables rule addition/removal, NetfilterQueue management,
    netlink socket timeout setup, threading, and monitoring for asynchronous
    stop requests.

    Has a NetfilterQueue instance rather than sub-classing it, because it
    encapsulates a thread and other fields, and does not need to modify any
    methods of the NetfilterQueue object.

    The results are undefined if start() or stop() are called multiple times.
    """

    fmt = 'iptables %s %s -t %s -j NFQUEUE --queue-num %d'
    _PROTO = {
        0x04: 'udp',
        0x06: 'tcp',
    }
    TIMEOUT_SECS = 0.5
    
    def __init__(self, config):
        super(NfQueueMonitor, self).__init__(config)

        # e.g. iptables <-I> <INPUT> -t <mangle> -j NFQUEUE --queue-num <0>'

        # Specifications
        self.nqo = None
        self.chain = None
        self.table = None
        self._callback = None
        self._rule = None
        self._nfqueue = netfilterqueue.NetfilterQueue()
        self._sk = None
        self._stopflag = False
        self._thread = None

        # State
        self._rule_added = False
        self._bound = False
        self._started = False

        if self.config.get('chain') == 'OUTPUT':
            self.logger.error("OUTPUT CHAIN")

    def __repr__(self):
        return '%s/%s@%d' % (self.chain, self.table, self.qno)
    
    def initialize(self):
        if not super(NfQueueMonitor, self).initialize():
            return False
    
        self.qno = self.config.get('qno', None)
        self.chain = self.config.get('chain', None)
        self.table = self.config.get('table', None)
        self._callback = self.config.get('callback', None)

        if self.qno is None or self.chain is None or self.table is None:
            return False
        
        if self._callback is None:
            return False

        self._rule = IptCmdTemplate(self.fmt, [self.chain, self.table, self.qno])
        return True

    def start(self):
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
            # self._nfqueue.bind(self.qno, self._callback)
            self._nfqueue.bind(self.qno, self._process)
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
        self._sk.settimeout(self.config.get('timeout_secs', self.TIMEOUT_SECS))

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
    
    def _process(self, pkt):
        bytez = pkt.get_payload()
        ip_packet = utils.ip_packet_from_bytez(bytez)
        tport=utils.tport_from_ippacket(ip_packet)
        
        if self.is_mangle(ip_packet):
            new_ip_packet = self.mangler.mangle(ip_packet)
            if new_ip_packet is not None:
                ip_packet = new_ip_packet
                tport = utils.tport_from_ippacket(ip_packet)
            pkt.set_payload(str(ip_packet))
        pkt.accept()
        return True

    