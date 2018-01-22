import dpkt
import socket
import logging
from diverters import utils
from diverters.linux import utils as lutils

class PacketHandler(object):
    """Used to encapsulate common patterns in packet hooks."""

    def __init__(self, pkt, diverter, label, callbacks3, callbacks4):
        self.logger = logging.getLogger('Diverter')

        self.pkt = pkt
        self.diverter = diverter  # Relies on Diverter for certain operations
        self.label = label
        self.callbacks3 = callbacks3
        self.callbacks4 = callbacks4

        self.raw = self.pkt.get_payload()
        self.ipver = ((ord(self.raw[0]) & 0xf0) >> 4)
        self.hdr, self.proto = self.diverter.parse_pkt[self.ipver](self.raw)

    def handle_pkt(self):
        """Generic packet hook.

        1.) Common prologue:
            A.) Unconditionally Write unmangled packet to pcap
            B.) Parse IP packet

        2.) Call layer 3 (network) callbacks...

        3.) Parse higher-layer protocol (TCP, UDP) for port numbers

        4.) Call layer 4 (transport) callbacks...

        5.) Common epilogue:
            A.) If the packet headers have been modified:
                i.) Double-write the mangled packet to the pcap for SSL
                    decoding purposes
                ii.) Update the packet payload with NetfilterQueue
            B.) Accept the packet with NetfilterQueue
        """

        # 1A: Unconditionally write unmangled packet to pcap
        self.diverter.write_pcap(self.hdr.pack())

        if (self.hdr, self.proto) == (None, None):
            self.logger.warning('%s: Failed to parse IP packet' % (self.label))
        else:
            proto_name = self.diverter.handled_protocols.get(self.proto)
            msg = '<%s> %s %s' % ('GENPKT', self.label,
                                  self.diverter.hdr_to_str(proto_name, self.hdr))
            self.diverter.logger.debug(msg)
            #self.diverter.pdebug(DGENPKT, '%s %s' % (self.label,
            #                     self.diverter.hdr_to_str(proto_name,
            #                     self.hdr)))

            # 1B: Parse IP packet (actually done in ctor)
            self.src_ip = socket.inet_ntoa(self.hdr.src)
            self.dst_ip = socket.inet_ntoa(self.hdr.dst)

            # 2: Call layer 3 (network) callbacks
            for cb in self.callbacks3:
                # These debug outputs are useful for figuring out which
                # callback is responsible for an exception that was masked by
                # python-netfilterqueue's global callback.
                self.diverter.logger.debug('<DCB> Calling %s' % (cb,))

                cb(self.label, self.hdr, self.ipver, self.proto, proto_name,
                   self.src_ip, self.dst_ip)

                self.diverter.logger.debug('<DCB> %s finished' % (cb,))

            if proto_name:
                if len(self.callbacks4):
                    # 3: Parse higher-layer protocol
                    self.sport = self.hdr.data.sport
                    self.dport = self.hdr.data.dport
                    self.skey = utils.gen_endpoint_key(proto_name,
                                                               self.src_ip,
                                                               self.sport)
                    self.dkey = utils.gen_endpoint_key(proto_name,
                                                               self.dst_ip,
                                                               self.dport)

                    pid, comm = lutils.get_pid_comm_by_endpoint(
                         self.ipver, proto_name, self.src_ip, self.sport)

                    if proto_name == 'UDP':
                        fmt = '| {label} {proto} | {pid:>6} | {comm:<8} | {src:>15}:{sport:<5} | {dst:>15}:{dport:<5} | {length:>5} | {flags:<11} | {seqack:<35} |'
                        logline = fmt.format(
                                label=self.label,
                                proto=proto_name,
                                pid=pid,
                                comm=comm,
                                src=self.src_ip,
                                sport=self.sport,
                                dst=self.dst_ip,
                                dport=self.dport,
                                length=len(self.raw),
                                flags='',
                                seqack='',
                            )
                        self.diverter.logger.debug('<DGENPKTV> %s' % (logline,))

                    elif proto_name == 'TCP':
                        tcp = self.hdr.data
                        # Interested in:
                        # SYN
                        # SYN,ACK
                        # ACK
                        # PSH
                        # FIN
                        syn = (tcp.flags & dpkt.tcp.TH_SYN) != 0
                        ack = (tcp.flags & dpkt.tcp.TH_ACK) != 0
                        fin = (tcp.flags & dpkt.tcp.TH_FIN) != 0
                        psh = (tcp.flags & dpkt.tcp.TH_PUSH) != 0
                        rst = (tcp.flags & dpkt.tcp.TH_RST) != 0

                        sa = 'Seq=%d, Ack=%d' % (tcp.seq, tcp.ack)
                        f = []
                        if rst:
                            f.append('RST')
                        if syn:
                            f.append('SYN')
                        if ack:
                            f.append('ACK')
                        if fin:
                            f.append('FIN')
                        if psh:
                            f.append('PSH')

                        fmt = '| {label} {proto} | {pid:>6} | {comm:<8} | {src:>15}:{sport:<5} | {dst:>15}:{dport:<5} | {length:>5} | {flags:<11} | {seqack:<35} |'
                        logline = fmt.format(
                                label=self.label,
                                proto=proto_name,
                                pid=pid,
                                comm=comm,
                                src=self.src_ip,
                                sport=self.sport,
                                dst=self.dst_ip,
                                dport=self.dport,
                                length=len(self.raw),
                                flags=','.join(f),
                                seqack=sa,
                            )
                        msg = '<DGENPKTV> %s' % (logline,)
                        self.diverter.logger.debug(msg)

                    try:
                        self.logger.info('  pid:  %d name: %s' %
                                            (pid, comm if comm else 'Unknown'))
                    except:
                        pass

                    hdr_latest = self.hdr
                    modified = False

                    # 4: Layer 4 (Transport layer) callbacks
                    for cb in self.callbacks4:
                        # These debug outputs are useful for figuring out which
                        # callback is responsible for an exception that was
                        # masked by python-netfilterqueue's global callback.

                        self.diverter.logger.debug('<DCB> Calling %s' % (cb,))

                        hdr_mod = cb(self.label, pid, comm, self.ipver,
                                     hdr_latest, proto_name,
                                     self.src_ip, self.sport, self.skey,
                                     self.dst_ip, self.dport, self.dkey)

                        if hdr_mod:
                            hdr_latest = hdr_mod
                            modified = True

                        msg = '<DCB> %s finished' % (cb,)
                        self.diverter.logger.debug(msg)

                    if modified:
                        # 5Ai: Double write mangled packets to represent changes
                        # made by FakeNet-NG while still allowing SSL decoding
                        self.diverter.write_pcap(hdr_latest.pack())

                        # 5Aii: Finalize changes with nfq
                        self.pkt.set_payload(hdr_latest.pack())
            else:
                msg = '<DGENPKT> %s: Not handling %s' % (self.label, self.proto)
                self.diverter.logger.debug(msg)

        # 5B: NF_ACCEPT
        self.pkt.accept()