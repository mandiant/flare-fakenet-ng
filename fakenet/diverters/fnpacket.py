import dpkt
import socket
import logging
import debuglevels


class PacketCtx(object):
    """Library-agnostic representation of packet and metadata.

    Attempt to abstract the following out of FakeNet-NG code:
    * OS-specific metadata
    * Packet display
    * Packet mangling
    * Use of underlying packet libraries e.g. dpkt
    """

    @staticmethod
    def gen_endpoint_key(proto, ip, port):
        """e.g. 192.168.19.132:tcp/3030

        Need static method because getOriginalDestPort (called by proxy
        listener) uses this.
        """
        return str(ip) + ':' + str(proto) + '/' + str(port)

    def __init__(self, label, raw):
        self.logger = logging.getLogger('Diverter')

        # Universal parameters
        self.label = label
        self._raw = raw
        self._mangled = False       # Determines whether to recalculate csums

        self.handled_protocols = {
            dpkt.ip.IP_PROTO_TCP: 'TCP',
            dpkt.ip.IP_PROTO_UDP: 'UDP',
        }

        self._is_ip = False
        self._is_icmp = False

        # Some packet attributes are cached in duplicate members below for code
        # simplicity and uniformity rather than having to query which packet
        # headers were or were not parsed.

        # L3 (IP) parameters
        self.ipver = None
        self._ipcsum0 = None        # Initial checksum
        self._hdr = None
        self.proto_num = None
        self.proto = None           # Abused as flag: is L4 protocol handled?
        self._src_ip0 = None        # Initial source IP address
        self._src_ip = None         # Cached in ASCII form
        self._dst_ip0 = None        # Initial destination IP address
        self._dst_ip = None         # Again cached in ASCII

        # L4 (TCP or UDP) parameters
        self._tcpudpcsum0 = None    # Initial checksum
        self._sport0 = None         # Initial source port
        self._sport = None          # Cached for uniformity/ease
        self.skey = None
        self._dport0 = None         # Initial destination port
        self._dport = None          # Cached for uniformity/ease
        self.dkey = None

        # Parse as much as possible
        self.ipver = ((ord(self._raw[0]) & 0xf0) >> 4)
        if self.ipver == 4:
            self._parseIpv4()
        elif self.ipver == 6:
            self._parseIpv6()
        self._parseIp()             # If _parseIpv4 or _parseIpv6 worked...
        self._parseIcmp()           # Or handle ICMP packets

    def __len__(self):
        if self._mangled:
            self._updateRaw()

        return len(self._raw)

    # Data

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

    # csums (NOTE: IPv6 has no csum, will return None)

    @property
    def l3csum0(self):
        return self._ipcsum0

    @property
    def l3csum(self):
        if self.ipver == 4:
            return self._hdr.sum
        return None

    @property
    def l4csum0(self):
        return self._tcpudpcsum0

    @property
    def l4csum(self):
        if self.proto:
            return self._hdr.data.sum
        return None

    # src_ip

    @property
    def src_ip0(self):
        return self._src_ip0

    @property
    def src_ip(self):
        return self._src_ip

    @src_ip.setter
    def src_ip(self, new_srcip):
        if self._is_ip:
            self._src_ip = new_srcip
            self._hdr.src = socket.inet_aton(new_srcip)
            self._mangled = True

    # dst_ip

    @property
    def dst_ip0(self):
        return self._dst_ip0

    @property
    def dst_ip(self):
        return self._dst_ip

    @dst_ip.setter
    def dst_ip(self, new_dstip):
        if self._is_ip:
            self._dst_ip = new_dstip
            self._hdr.dst = socket.inet_aton(new_dstip)
            self._mangled = True

    # sport

    @property
    def sport0(self):
        return self._sport0

    @property
    def sport(self):
        return self._sport

    @sport.setter
    def sport(self, new_sport):
        if self._is_ip:
            self._sport = new_sport
            self._hdr.data.sport = new_sport
            self._mangled = True

    # dport

    @property
    def dport0(self):
        return self._dport0

    @property
    def dport(self):
        return self._dport

    @dport.setter
    def dport(self, new_dport):
        if self._is_ip:
            self._dport = new_dport
            self._hdr.data.dport = new_dport
            self._mangled = True

    # ICMP

    @property
    def is_icmp(self):
        return self._is_icmp

    @property
    def icmp_type(self):
        if self._is_icmp:
            return self._hdr.data.type
        return None

    @property
    def icmp_code(self):
        if self._is_icmp:
            return self._hdr.data.code
        return None

    def fmtL3Csums(self):
        s = 'IP csum N/A'
        if self._is_ip:
            if self.ipver == 4:
                csum0 = hex(self._ipcsum0).rstrip('L')
                if self._mangled:
                    self._calcCsums()
                    csum = hex(self._hdr.sum).rstrip('L')
                    s = 'IPv4 csum %s->%s' % (csum0, csum)
                else:
                    s = 'IPv4 csum %s' % (csum0)
            elif self.ipver == 6:
                s = 'IPv6 csum N/A'
        return s

    def fmtL4Csums(self):
        s = 'L4 csum N/A'
        if self.proto:
            csum0 = hex(self._tcpudpcsum0).rstrip('L')
            if self._mangled:
                self._calcCsums()
                csum = hex(self._hdr.data.sum).rstrip('L')
                s = '%s csum %s->%s' % (self.proto, csum0, csum)
            else:
                s = '%s csum %s' % (self.proto, csum0)
        return s

    def fmtCsumData(self, sep='/'):
        if self._is_ip:
            return '%s %s %s ' % (self.fmtL3Csums(), sep, self.fmtL4Csums())
        else:
            return 'No identifying info'

    def hdrToStr2(self, sep='/'):
        return '%s %s %s' % (self.hdrToStr(), sep, self.fmtCsumData(sep))

    def hdrToStr(self):
        s = 'No valid IP headers parsed'
        if self._is_ip:
            if self.proto:
                s = '%s %s:%d->%s:%d' % (self.proto, self._src_ip,
                                         self._hdr.data.sport, self._dst_ip,
                                         self._hdr.data.dport)
            else:
                s = '%s->%s' % (self._src_ip, self._dst_ip)

        return s

    def _parseIp(self):
        """Parse IP src/dst fields and next-layer fields if recognized."""
        if self._is_ip:
            self._src_ip0 = self._src_ip = socket.inet_ntoa(self._hdr.src)
            self._dst_ip0 = self._dst_ip = socket.inet_ntoa(self._hdr.dst)
            self.proto = self.handled_protocols.get(self.proto_num)

            # If this is a transport protocol we handle...
            if self.proto:
                self._tcpudpcsum0 = self._hdr.data.sum
                self._sport0 = self._sport = self._hdr.data.sport
                self._dport0 = self._dport = self._hdr.data.dport
                self.skey = self._genEndpointKey(self._src_ip, self._sport)
                self.dkey = self._genEndpointKey(self._dst_ip, self._dport)

    def _genEndpointKey(self, ip, port):
        return PacketCtx.gen_endpoint_key(self.proto, ip, port)

    def _parseIcmp(self):
        self._is_icmp = (self.proto_num == dpkt.ip.IP_PROTO_ICMP)

    def _parseIpv4(self):
        hdr = dpkt.ip.IP(self._raw)
        # An IP header length less than 5 is invalid
        if hdr.hl >= 5:
            self._is_ip = True
            self._hdr = hdr
            self.proto_num = hdr.p
            self._ipcsum0 = hdr.sum
        return bool(self._hdr)

    def _parseIpv6(self):
        self._is_ip = True
        self._hdr = dpkt.ip6.IP6(self._raw)
        self.proto_num = self._hdr.nxt
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


