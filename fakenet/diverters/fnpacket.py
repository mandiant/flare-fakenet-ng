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
        self._raw = raw
        self._mangled = False # Used to determine whether to recalculate csums

        self.handled_protocols = {
            dpkt.ip.IP_PROTO_TCP: 'TCP',
            dpkt.ip.IP_PROTO_UDP: 'UDP',
        }

        self._is_ip = False
        self._is_icmp = False

        # L3 parameters
        self.ipver = None
        self._hdr = None
        self.proto = None
        self.proto_name = None
        self._src_ip0 = None # Initial source IP address
        self._src_ip = None
        self._dst_ip0 = None # Initial destination IP address
        self._dst_ip = None

        # L4 parameters
        self.sport0 = None # Initial source port
        self._sport = None
        self.skey = None
        self.dport0 = None # Initial destination port
        self._dport = None
        self.dkey = None

        # Parse as much as possible
        self.ipver = ((ord(self._raw[0]) & 0xf0) >> 4)
        if self.ipver == 4:
            self._parseIpv4()
        elif self.ipver == 6:
            self._parseIpv6()

        self._parseIp()
        self._parseIcmp()

    def __len__(self):
        if self._mangled:
            self._updateRaw()

        return len(self._raw)

    @property
    def mangled(self):
        return self._mangled

    @property
    def hdr(self):
        if self._mangled:
            self._calcCsums()

        return self._hdr

    @property
    def octets(self):
        if self._mangled:
            self._updateRaw()

        return self._raw

    @property
    def src_ip(self):
        return self._src_ip

    @src_ip.setter
    def src_ip(self, new_srcip):
        if self._is_ip:
            self._src_ip = new_srcip
            self._hdr.src = socket.inet_aton(new_srcip)
            self._mangled = True

    @property
    def dst_ip(self):
        return self._dst_ip

    @dst_ip.setter
    def dst_ip(self, new_dstip):
        if self._is_ip:
            self._dst_ip = new_dstip
            self._hdr.dst = socket.inet_aton(new_dstip)
            self._mangled = True

    @property
    def sport(self):
        return self._sport

    @sport.setter
    def sport(self, new_sport):
        if self._is_ip:
            self._sport = new_sport
            self._hdr.sport = new_sport
            self._mangled = True

    @property
    def dport(self):
        return self._dport

    @dport.setter
    def dport(self, new_dport):
        if self._is_ip:
            self._dport = new_dport
            self._hdr.dport = new_dport
            self._mangled = True

    @property
    def is_icmp(self): return self._is_icmp

    @property
    def icmp_type(self):
        return self._hdr.data.type if self._is_icmp else None

    @property
    def icmp_code(self):
        return self._hdr.data.code if self._is_icmp else None

    def hdrToStr(self):
        s = 'No valid IP headers parsed'
        if self._is_ip:
            if self.proto_name:
                s = '%s %s:%d->%s:%d' % (self.proto_name, self._src_ip,
                                         self._hdr.data.sport, self._dst_ip,
                                         self._hdr.data.dport)
            else:
                s = '%s->%s' % (self._src_ip, self._dst_ip)

        return s

    def _parseIp(self):
        if self._is_ip:
            self._src_ip0 = self._src_ip = socket.inet_ntoa(self._hdr.src)
            self._dst_ip0 = self._dst_ip = socket.inet_ntoa(self._hdr.dst)
            self.proto_name = self.handled_protocols.get(self.proto)
            if self.proto_name: # If this is a transport protocol we handle...
                self.sport0 = self._sport = self._hdr.data.sport
                self.dport0 = self._dport = self._hdr.data.dport
                self.skey = self._genEndpointKey(self._src_ip, self._sport)
                self.dkey = self._genEndpointKey(self._dst_ip, self._dport)

    def _genEndpointKey(self, ip, port):
        return PacketCtx.gen_endpoint_key(self.proto_name, ip, port)

    def _parseIcmp(self):
        self._is_icmp = (self.proto == dpkt.ip.IP_PROTO_ICMP)

    def _parseIpv4(self):
        hdr = dpkt.ip.IP(self._raw)
        # An IP header length less than 5 is invalid
        if hdr.hl >= 5:
            self._is_ip = True
            self._hdr = hdr
            self.proto = hdr.p
        return bool(self._hdr)

    def _parseIpv6(self):
        self._is_ip = True
        self._hdr = dpkt.ip6.IP6(self._raw)
        self.proto = self._hdr.nxt
        return True

    def _calcCsums(self):
        """The roundabout dance of inducing dpkt to recalculate checksums..."""
        self._hdr.sum = 0
        self._hdr.data.sum = 0
        # This has the side-effect of invoking dpkt.in_cksum() et al:
        str(self._hdr)

    def _updateRaw(self):
        self._calcCsums()
        self._raw = self._hdr.pack()

