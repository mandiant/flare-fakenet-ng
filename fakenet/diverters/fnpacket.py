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

    @staticmethod
    def gen_endpoint_key(proto_name, ip, port):
        """e.g. 192.168.19.132:tcp/3030"""
        return str(ip) + ':' + str(proto_name) + '/' + str(port)


    def __init__(self, label, raw):
        # Universal parameters
        self.label = label
        self.raw = raw

        self.handled_protocols = {
            dpkt.ip.IP_PROTO_TCP: 'TCP',
            dpkt.ip.IP_PROTO_UDP: 'UDP',
        }

        # L3 parameters
        self.ipver = None
        self.hdr = None
        self.proto = None
        self.proto_name = None
        self._src_ip = None
        self._dst_ip = None

        # L4 parameters
        self.sport = None
        self.skey = None
        self.dport = None
        self.dkey = None

        # Parse as much as possible
        self.ipver = ((ord(self.raw[0]) & 0xf0) >> 4)
        if self.ipver == 4:
            self._parseIpv4()
        elif self.ipver == 6:
            self._parseIpv6()

        self._parseIp()
        self._parseIcmp()

    @property
    def src_ip(self):
        """No setter until mangling support is added."""
        return self._src_ip

    @property
    def dst_ip(self):
        """No setter until mangling support is added."""
        return self._dst_ip

    def _parseIp(self):
        if self.hdr:
            self.proto_name = self.handled_protocols.get(self.proto)
            if self.proto_name: # If this is a transport protocol we handle...
                self.sport = self.hdr.data.sport
                self.dport = self.hdr.data.dport
                self.skey = self._genEndpointKey(self._src_ip, self.sport)
                self.dkey = self._genEndpointKey(self._dst_ip, self.dport)
            self._src_ip = socket.inet_ntoa(self.hdr.src)
            self._dst_ip = socket.inet_ntoa(self.hdr.dst)

    def _genEndpointKey(self, ip, port):
        return PacketCtx.gen_endpoint_key(self.proto_name, ip, port)

    def _parseIcmp(self):
        self.is_icmp = (self.proto == dpkt.ip.IP_PROTO_ICMP)

    def _parseIpv4(self):
        hdr = dpkt.ip.IP(self.raw)
        # An IPv6 header length less than 5 is invalid
        if hdr.hl >= 5:
            self.hdr = hdr
            self.proto = hdr.p
        return bool(self.hdr)

    def _parseIpv6(self):
        hdr = dpkt.ip6.IP6(self.raw)
        self.hdr = hdr
        self.proto = hdr.nxt
        return True

    # ICMP accessors
    def isIcmp(self): return self.is_icmp

    def icmpType(self):
        if self.is_icmp:
            return self.hdr.data.type

    def icmpCode(self):
        if self.is_icmp:
            return self.hdr.data.code

    def hdrToStr(self):
        s = 'No valid IP headers parsed'
        if self.hdr:
            if self.proto_name:
                s = '%s %s:%d->%s:%d' % (self.proto_name, self._src_ip,
                                         self.hdr.data.sport, self._dst_ip,
                                         self.hdr.data.dport)
            else:
                s = '%s->%s' % (self._src_ip, self._dst_ip)

        return s

