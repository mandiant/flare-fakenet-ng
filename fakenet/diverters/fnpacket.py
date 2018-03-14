import dpkt
import socket


class PacketCtx(object):
    """Library-agnostic representation of packet and metadata.
    
    Attempt to abstract the following out of FakeNet-NG code:
    * OS-specific metadata
    * Packet display
    * Packet mangling
    * Use of underlying packet libraries e.g. dpkt
    """
    def __init__(self, label, raw):
        # Universal parameters
        self.label = label
        self.raw = raw

        # L3 parameters
        self.ipver = None
        self.hdr = None
        self.proto = None
        self.proto_name = None
        self.src_ip = None
        self.dst_ip = None

        # L4 parameters
        self.sport = None
        self.skey = None
        self.dport = None
        self.dkey = None

        # Parse as much as possible
        self.ipver = ((ord(self.raw[0]) & 0xf0) >> 4)
        if self.ipver == 4:
            self.parse_ipv4()
        elif self.ipver == 6:
            self.parse_ipv6()

    def parse_ipv4(self):
        hdr = dpkt.ip.IP(self.raw)
        # An IPv6 header length less than 5 is invalid
        if hdr.hl >= 5:
            self.hdr = hdr
            self.proto = hdr.p
        return bool(self.hdr)

    def parse_ipv6(self):
        hdr = dpkt.ip6.IP6(self.raw)
        self.hdr = hdr
        self.proto = hdr.nxt
        return True

    def hdr_to_str(self):
        s = 'No valid headers parsed'
        if self.hdr:
            src_ip = socket.inet_ntoa(self.hdr.src)
            dst_ip = socket.inet_ntoa(self.hdr.dst)
            if self.proto_name:
                s = '%s %s:%d->%s:%d' % (self.proto_name, src_ip,
                                         self.hdr.data.sport, dst_ip,
                                         self.hdr.data.dport)
            else:
                s = '%s->%s' % (src_ip, dst_ip)

        return s

