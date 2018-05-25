
from scapy.all import TCP, UDP
from diverters import fnpacket


class DarwinPacketCtx(fnpacket.PacketCtx):
    def __init__(self, lbl, ip_packet):
        super(DarwinPacketCtx, self).__init__(lbl, str(ip_packet))
        self.to_inject = True
        self.ip_packet = ip_packet
        if TCP in ip_packet:
            self.protocol = 'tcp'
        elif UDP in ip_packet:
            self.protocol = 'udp'
        else:
            self.protocol = ''
    
    def get_current_dkey(self):
        return self._genEndpointKey(self.dst_ip, self.dport)
    
    def get_current_skey(self):
        return self._genEndpointKey(self.src_ip, self.sport)



class DarwinKextPacketCtx(DarwinPacketCtx):
    def __init__(self, meta, lbl, ip_packet):
        super(DarwinKextPacketCtx, self).__init__(lbl, ip_packet)
        self.meta = meta