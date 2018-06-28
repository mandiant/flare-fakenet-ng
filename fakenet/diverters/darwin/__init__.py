
import logging
import os
import netifaces
import subprocess as sp
from diverters.diverterbase import DiverterBase
from diverters.darwin import utils as dutils

class DarwinDiverter(DiverterBase):
    def __init__(self, diverter_config, listeners_config, ip_addrs,
                 logging_level=logging.INFO):
        super(DarwinDiverter, self).__init__(diverter_config, listeners_config,
                                             ip_addrs, logging_level)

        self.gw = None
        self.iface = None
        self.pid = os.getpid()

    def __del__(self):
        self.stopCallback()

    def initialize(self):
        self.gw = dutils.get_gateway_info()
        if self.gw is None:
            raise NameError("Failed to get gateway")

        self.iface = dutils.get_iface_info(self.gw.get('iface'))
        if self.iface is None:
            raise NameError("Failed to get public interface")

        return


    #--------------------------------------------------------------
    # implements various DarwinUtilsMixin methods
    #--------------------------------------------------------------

    def check_active_ethernet_adapters(self):
        return len(netifaces.interfaces()) > 0

    def check_ipaddresses(self):
        return True

    def check_dns_servers(self):
        return True

    def check_gateways(self):
        return len(netifaces.interfaces()) > 0

    def _get_pid_comm_through_lsof(self, ipkt):
        if not ipkt.protocol == 'tcp' and not ipkt.protocol == 'udp':
            return None, None

        protospec = "-i%s%s@%s" % (
            ipkt.ip_packet.version, ipkt.protocol, ipkt.dst_ip)

        if ipkt.dport:
            protospec = "%s:%s" % (protospec, ipkt.dport)
        cmd = [
            'lsof', '-wnPF', 'cLn',
            protospec
        ]

        try:
            result = sp.check_output(cmd, stderr=None).strip()
        except:
            result = None

        if result is None:
            return None, None

        lines = result.split('\n')
        for record in self._generate_records(lines):
            _result = self._parse_record(record)
            if _result is None:
                continue
            if self._is_my_packet(_result):
                return _result.get('pid'), _result.get('comm')

        return None, None

    def _generate_records(self, lines):
        n = len(lines)
        maxlen = (n // 5) * 5
        lines = lines[:maxlen]
        for i in xrange(0, len(lines), 5):
            try:
                record = lines[i:i+5]
                pid = record[0][1:]
                comm = record[1][1:]
                uname = record[2][1:]
                name = record[4][1:]
                yield {'pid': pid, 'comm': comm, 'name': name, 'uname': uname}
            except IndexError:
                yield {}

    def _parse_record(self, record):
        name = record.get('name')
        if name is None:
            return None

        try:
                src_endpoint, dst_endpoint = name.split('->')
                src, sport = src_endpoint.split(':')
                dst, dport = dst_endpoint.split(':')
        except:
            return None

        record.update({'src': src, 'dst': dst, 'sport': sport, 'dport': dport})
        record['pid'] = int(record.get('pid'))
        return record
