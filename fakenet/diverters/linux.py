import dpkt
import time
import socket
import logging
import threading
import subprocess
import diverterbase
import netfilterqueue
from linutil import *
from collections import namedtuple
from diverterbase import DiverterBase
from netfilterqueue import NetfilterQueue

b2 = lambda x: '1' if x else '0'

class LinuxDiverterNetfilterQueue:
    """NetfilterQueue object wrapper.
    
    Uses the has-a relationship rather than sub-classing because it
    encapsulates a thread and other fields, and does not modify any methods of
    the NetfilterQueue object.
    """

    def __init__(self, qno, chain, table, callback):
        self.qno = qno
        self.chain = chain
        self.table = table
        self._callback = callback
        self._nfqueue = NetfilterQueue()
        self._sk = None
        self._stopflag = False
        self._thread = None

    def _gen_cmd(self, ins_or_del):
        return 'iptables -t %s ' + ins_or_del + ' %s -j NFQUEUE --queue-num %d'

    def gen_add_cmd(self):
        return (self._gen_cmd('-I') % (self.chain, self.table, self.qno))

    def gen_del_cmd(self):
        return (self._gen_cmd('-D') % (self.chain, self.table, self.qno))

    def start(self, timeout_sec=0.5):
        """
        Binds to the netfilter queue number specified in the ctor, obtains the
        nfq socket, sets a timeout of <timeout_sec>, and starts the thread
        procedure which checks _stopflag every <timeout_sec> seconds.
        """
        # Bind the specified callback to the specified queue
        self._nfqueue.bind(self.qno, self._callback)

        # Facilitate _stopflag monitoring and thread joining
        self._sk = socket.fromfd(self._nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        self._sk.settimeout(timeout_sec)

        self._thread = threading.Thread(target=self._threadproc)
        # self._thread.daemon = True
        self._stopflag = False
        self._thread.start()

    def _threadproc(self):
        while not self._stopflag:
            try:
                self._nfqueue.run_socket(self._sk)
            except socket.timeout:
                # Ignore timeouts generated every N seconds due to the prior
                # call to settimeout(), and move on to evaluating the current
                # state of _stopflag.
                pass

    def stop_nonblocking(self):
        """Call this on each LinuxDiverterNetfilterQueue object in turn to stop
        them all as close as possible to the same time (likely within 1 sec of
        each other due to the socket timeout).
        
        Perfect synchrony is a non-goal because even though it can be achieved,
        halting the Diverter will still disrupt existing connections
        (redirected and otherwise). Hence, it is up to the user to halt
        FakeNet-NG after any critical network operations have concluded.
        """
        self._stopflag = True

    def stop(self):
        self.stop_nonblocking()
        self._thread.join()
        self._nfqueue.unbind()

class Diverter(DiverterBase, LinUtilMixin):
    def __init__(self, diverter_config, listeners_config, ip_addrs,
                 logging_level = logging.INFO):
        self.init_base(diverter_config, listeners_config, ip_addrs,
                       logging_level)
        self.init_diverter_linux()

    def init_diverter_linux(self):
        self.parse_pkt = dict()
        self.parse_pkt[4] = self.parse_ipv4
        self.parse_pkt[6] = self.parse_ipv6
        self._queues = list()

        self.handled_protocols = {
            dpkt.ip.IP_PROTO_TCP: 'TCP',
            dpkt.ip.IP_PROTO_UDP: 'UDP',
        }

        # Quick lookup of what unbound service ports have been redirected. This
        # is only used by the iptables-based implementation to determine
        # whether to create a new iptables rule.
        self.redirected = dict()

        # Port forwarding table, for looking up original unbound service ports
        # when sending replies to endpoints that have attempted to communicate
        # with unbound ports. Allows fixing up source ports in response
        # packets.

        self.port_fwd_table = dict()
        self.port_fwd_table_lock = threading.Lock()

    def get_current_nfnlq_bindings(self, procfs_path):
        """Determine what NFQUEUE queue numbers (if any) are already bound by
        existing libnfqueue client processes.
        
        Although iptables rules may exist specifying other queues in addition
        to these, the netfilter team does not support using libiptc (such as
        via python-iptables) to detect that condition, so code that does so may
        break in the future. Shelling out to iptables and parsing its output
        for NFQUEUE numbers is not an attractive option. The practice of
        checking the currently bound NetFilter netlink queue bindings seems
        like an adequate compromise. If an iptables rule specifies an NFQUEUE
        number that is not yet bound by any process in the system, that is a
        race condition that can be left up to the user to manage. We can add
        FakeNet arguments to be passed to the Diverter for handling this, if it
        becomes strictly necessary to provide that feature.
        """

        queues = list()
        with open(procfs_path, 'r') as f:
            lines = f.read().split('\n')
            for line in lines:
                line = line.strip()
                if line:
                    try:
                        queue_nr = int(line.split()[0], 10)
                        self.logger.debug('Found NFQUEUE #' + str(queue_nr) +
                                          ' per ' + procfs_path)
                        queues.append(queue_nr)
                    except:
                        pass

        return queues

    def get_next_queuenos(self, existing_queues, n):
        # Queue numbers are of type u_int16_t hence 0xffff being the maximum
        # possible queue number.
        next2 = list()
        for qno in xrange(1 + 0xffff):
            if qno not in existing_queues:
                next2.append(qno)
                if len(next2) == n:
                    break

        return next2

    def start(self):
        self.logger.info('Starting...')

        hookspec = namedtuple('hookspec', ['table', 'chain', 'callback'])
        callbacks = [
            hookspec('INPUT', 'mangle', self.handle_pkt_in_prerouting),
            hookspec('OUTPUT', 'mangle', self.handle_pkt_in_output),
        ]

        nhooks = len(callbacks)

        # Auto-sense the next N available NFQUEUE numbers and install hooks
        existing_queues = self.get_current_nfnlq_bindings('/proc/net/netfilter/nfnetlink_queue')
        qnos = self.get_next_queuenos(existing_queues, nhooks)
        if len(qnos) != nhooks:
            raise SystemError('Could not procure a sufficient number of ' +
                            'netfilter queue numbers')

        self.logger.debug('Next available NFQUEUE numbers: ' + str(qnos))

        self._queues = list()
        for qno, hook in zip(qnos, callbacks):
            ldnq = LinuxDiverterNetfilterQueue(qno, hook.chain, hook.table,
                                               hook.callback)
            self._queues.append(ldnq)

            # Remove rule if exists
            cmd = ldnq.gen_del_cmd()
            self.logger.debug(cmd)
            subprocess.call(cmd.split())

            # Add rule
            cmd = ldnq.gen_add_cmd()
            self.logger.debug(cmd)
            ret = subprocess.call(cmd.split())

            if ret != 0:
                raise SystemError('Failed to create %s/%s rule @ NFQUEUE #%d' %
                                  (hook.chain, hook.table, qno))

        # Only start queues one all iptables rules have been successfully
        # created
        for queue in self._queues:
            queue.start()

        # TODO: Duplicate windows.Diverter code for
        #   * # Set local DNS server IP address (if modifylocaldns)
        #   * # Stop DNS service (if stopdnsservice)
        #   * self.flush_dns() # ipconfig /flushdns

    def stop(self):
        self.logger.info('Stopping...')

        # Indicate that we are stopping and allow LinuxDiverterNetfilterQueue
        # threads to conclude their socket wait states.
        for queue in self._queues:
            cmd = queue.gen_del_cmd()
            self.logger.debug(cmd)
            ret = subprocess.call(cmd.split())
            if ret != 0:
                self.logger.error('Failed to remove %s/%s rule @ NFQUEUE #%d' %
                                  (queue.table, queue.chain, queue.qno))
            queue.stop_nonblocking()

        # Wait until all queues actually stop
        for queue in self._queues:
            self.logger.debug('Stopping %s/%s hook at NFQUEUE #%d' %
                             (queue.chain, queue.table, queue.qno))
            queue.stop()

        if self.pcap:
            self.pcap.close()

        self.logger.info('Stopped')

        # TODO: Duplicate windows.Diverter code for
        #   * # Restore DNS server (if modifylocaldns)
        #   * # Restart DNS service (if stopdnsservice)
        #   * self.flush_dns() # ipconfig /flushdns

    def parse_ipv4(self, ipver, raw):
        hdr = dpkt.ip.IP(raw)
        if hdr.hl < 5:
            return (-1, -1) # An IP header length less than 5 is invalid
        return hdr, hdr.p

    def parse_ipv6(self, ipver, raw):
        hdr = dpkt.ip6.IP6(raw)
        return hdr, hdr.nxt

    def gen_endpoint_key(self, proto_name, ip, port):
        """e.g. 192.168.19.132:3030/tcp"""
        return str(ip) + ':' + str(proto_name) + '/' + str(port)

    def handle_pkt_in_output(self, pkt):
        self.logger.debug('handle_pkt_in_output...')
        raw = pkt.get_payload()
        ipver = ((ord(raw[0]) & 0xf0) >> 4)
        hdr, proto = self.parse_pkt[ipver](ipver, raw)

        proto_name = self.handled_protocols.get(proto)

        if proto_name:
            dst_ip = socket.inet_ntoa(hdr.dst)
            dport = hdr.data.dport
            endpoint_key = self.gen_endpoint_key(proto_name, dst_ip, dport)

            # If the remote endpoint (IP/port/proto) combo corresponds to an
            # endpoint that initiated a conversation with an unbound port in
            # the past, then fix up the source port for this outgoing packet
            # with the last destination port that was requested by that
            # endpoint. The term "endpoint" is (ab)used loosely here to apply
            # to UDP host/port/proto combos and any other protocol that may be
            # supported in the future.
            self.port_fwd_table_lock.acquire()
            try:
                if endpoint_key in self.port_fwd_table:
                    self.logger.debug(' = FOUND endpoint key entry: ' + endpoint_key)
                    new_sport = self.port_fwd_table[endpoint_key]
                    hdr = self.mangle_srcport(hdr, proto_name, hdr.data.sport, new_sport)
                    pkt.set_payload(hdr.pack())
                else:
                    self.logger.debug(' ! NO SUCH endpoint key entry: ' + endpoint_key)
            finally:
                self.port_fwd_table_lock.release()

        self.write_pcap(hdr.pack())

        pkt.accept()

    def handle_pkt_in_prerouting(self, pkt):
        self.logger.debug('handle_pkt_in_prerouting...')

        raw = pkt.get_payload()
        ipver = ((ord(raw[0]) & 0xf0) >> 4)
        hdr, proto = self.parse_pkt[ipver](ipver, raw)

        proto_name = self.handled_protocols.get(proto)

        if proto_name:
            default = self.default_listener[proto_name]
            diverted_ports = self.diverted_ports.get(proto_name, [])
            src_ip = socket.inet_ntoa(hdr.src)
            sport = hdr.data.sport
            dst_ip = socket.inet_ntoa(hdr.dst)
            dport = hdr.data.dport

            endpoint_key = self.gen_endpoint_key(proto_name, src_ip, sport)

            if self.decide_redir(ipver, default, diverted_ports, src_ip, sport, dst_ip, dport):
                # Record the foreign endpoint and old destination port in the
                # port forwarding table
                self.logger.debug(' + ADDING endpoint key entry: ' + endpoint_key)
                self.port_fwd_table_lock.acquire()
                try:
                    self.port_fwd_table[endpoint_key] = dport
                finally:
                    self.port_fwd_table_lock.release()

                # Perform the redirection
                hdr_modified = self.redir(pkt, hdr, proto_name, dport, default)

                if hdr_modified:
                    hdr = hdr_modified
                    pkt.set_payload(hdr.pack())

            else:
                # Delete stale entries in the port forwarding table if the
                # foreign endpoint appears to be reusing a port that was
                # formerly used to connect to an unbound port. This prevents
                # the OUTPUT or other packet hook from faithfully overwriting
                # the source port to conform to the foreign endpoint's stale
                # connection port when the foreign host is reusing the port
                # number to connect to an already-bound port on the FakeNet
                # system.

                self.port_fwd_table_lock.acquire()
                try:
                    if endpoint_key in self.port_fwd_table:
                        self.logger.debug(' - DELETING endpoint key entry: ' + endpoint_key)
                        del self.port_fwd_table[endpoint_key]
                finally:
                    self.port_fwd_table_lock.release()

        else:
            self.logger.debug('Not handling protocol ' + str(proto))

        self.write_pcap(hdr.pack())

        pkt.accept()

    def decide_redir(self, ipver, default_port, bound_ports, src_ip, sport, dst_ip, dport):
        is_dummy_svc_port = (dport == default_port)

        # A, B, C, and D are for easy calculation of sum-of-products logical result
        # Full names are present for readability
        # TODO: Add commentation explaining minterms and SOP logic derived from
        # redir_logic.xlsx
        a = src_ip_is_local = (src_ip in self.ip_addrs[ipver])
        b = dst_ip_is_local = (dst_ip in self.ip_addrs[ipver])

        c = src_port_is_bound = sport in (bound_ports + self.redirected.keys())
        d = dst_port_is_bound = dport in (bound_ports + self.redirected.keys())

        self.logger.debug('srcip: ' + str(src_ip) + (' (local)' if a else ' (foreign)'))
        self.logger.debug('dstip: ' + str(dst_ip) + (' (local)' if b else ' (foreign)'))
        self.logger.debug('srcpt: ' + str(sport) + (' (bound)' if c else ' (unbound)'))
        self.logger.debug('dstpt: ' + str(dport) + (' (bound)' if d else ' (unbound)'))

        result = (
            (dst_ip_is_local and not src_ip_is_local and not dst_port_is_bound) or
            (src_ip_is_local and not src_port_is_bound and not dst_port_is_bound)
        )

        result = (b and not a and not d) or (a and not c and not d)

        self.logger.debug('abcd = ' + b2(a) + b2(b) + b2(c) + b2(d))

        return result

    def redir(self, pkt, hdr, proto_name, dstport, newdstport):
        self.logger.debug('REDIRECTING')
        hdr = self.mangle_dstport(hdr, proto_name, dstport, newdstport)
        return hdr

    def mangle_dstport(self, hdr, proto_name, dstport, newdstport):
        """Mangle destination port for selected incoming packets."""
        hdr.data.dport = newdstport
        self._calc_csums(hdr)
        return hdr

    def mangle_srcport(self, hdr, proto_name, srcport, newsrcport):
        """Mangle source port for selected outgoing packets."""
        hdr.data.sport = newsrcport
        self._calc_csums(hdr)
        return hdr

    def _calc_csums(self, hdr):
        """The roundabout dance of inducing dpkt to recalculate checksums."""
        hdr.sum = 0
        hdr.data.sum = 0
        str(hdr)  # This has the side-effect of invoking dpkt.in_cksum() et al

if __name__ == '__main__':
    logging.basicConfig(format='%(message)s')
    diverterbase.test_redir_logic(Diverter)
