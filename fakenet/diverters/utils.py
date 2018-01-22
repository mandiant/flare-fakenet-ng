from scapy.all import TCP, UDP
import subprocess as sp
import netifaces
import hashlib

from diverters import constants


def tport_from_ippacket(ip_packet):
    '''
    Return the transport object (either TCP or UDP) from scappy IP object
    @param ip_packet: scapy IP packet object
    @return None on error, TCP or UDP on success
    '''
    tport = None
    try:
        if UDP in ip_packet:
            tport = ip_packet[UDP]
        elif TCP in ip_packet:
            tport = ip_packet[TCP]
        else:
            tport = None
    except:
        tport = None
    return tport


def gethash(s):
    '''
    Calculate the hash of the input string like data
    @return hashstring
    '''
    md = hashlib.md5()
    md.update(s)
    return md.hexdigest()


def get_iface_info(ifname):
    '''Gather interface information using its name
    @return dictionary {
        'addr.inet':    list of IP addrseses assigned to this interface,
        'addr.dlink':   hardware/MAC address of this interface
        'iface':        interface name
        } or None if error occurs
    '''
    if ifname not in netifaces.interfaces():
        return None

    addrs = netifaces.ifaddresses(ifname)
    ipaddrs = [_.get('addr') for _ in addrs.get(netifaces.AF_INET, dict())]
    if len(ipaddrs) < 1:
        return None

    hwaddr = addrs.get(netifaces.AF_LINK, list())[0].get('addr', None)
    if hwaddr is None:
        return None
    return {'addr.inet': ipaddrs, 'addr.dlink': hwaddr, 'iface': ifname}


def get_gateway_info():
    '''
    Gather default gateway information
    @return dictionary {
        'addr.inet'     :   Gateway IP address
        'addr.dlink'    :   Gateway hardware/MAC address
        'iface'         :   Interface to communicate with default gateway
    } or None if error occurs
    '''
    gwlist = netifaces.gateways().get('default', None)
    if gwlist is None:
        return None
    inetgw = gwlist.get(netifaces.AF_INET, None)
    if inetgw is None:
        return None

    gwip, gwif = inetgw[0], inetgw[1]
    ifinfo = get_iface_info(gwif)
    if ifinfo is None:
        return None
    p = sp.Popen('arp -n %s' % gwip, shell=True, stdout=sp.PIPE)
    (output, _) = p.communicate()
    if 'no entry' in output:
        return None
    try:
        gwmac = output.split(' ')[3]
    except:
        return None
    return {'iface': gwif, 'addr.inet': gwip, 'addr.dlink': gwmac}


def get_ip_version(bytez):
    return ((ord(bytez[0]) & 0xf0) >> 4)

def gen_endpoint_key(tport, ip, port):
    return '%s://%s:%s' % (str(tport), str(ip), str(port))


def execute_detached(execute_cmd, winders=False, logger=None):
    """Supposedly OS-agnostic asynchronous subprocess creation.

    Written in anticipation of re-factoring diverters into a common class
    parentage.

    Not tested on Windows. Override or fix this if it does not work, for
    instance to use the Popen creationflags argument or omit the close_fds
    argument on Windows.
    """
    logger = logging.getLogger() if logger is None else logger
    DETACHED_PROCESS = 0x00000008
    cflags = DETACHED_PROCESS if winders else 0
    cfds = False if winders else True
    shl = False if winders else True

    def ign_sigint():
        # Prevent KeyboardInterrupt in FakeNet-NG's console from
        # terminating child processes
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    try:
        pid = subprocess.Popen(execute_cmd, creationflags=cflags,
                               shell=shl, close_fds = cfds,
                               preexec_fn=ign_sigint).pid
    except Exception, e:
        logger.error('Error: Failed to execute command: %s', execute_cmd)
        logger.error('       %s', e)
    return pid


def parse_listeners_config(listeners_config, logger=None):
    logger = logging.getLogger() if logger is None else logger
    supported_protocols = ['TCP', 'UDP']
    
    result = {'TCP': dict(), 'UDP': dict()}

    for lname, lconf in listeners_config.iteritems():
        try:
            port = lconf.get('port', None)
        except:
            port = None

        if port is None:
            logger.error('Bad %s listener config: missing port' % (lname,))
            return None
        
        proto = lconf.get('protocol', 'NONE').upper()
        if not proto in supported_protocols:
            logger.error('Bad %s listener config: missing protocol' % (lname,))
            return None
        
        hidden = lconf.get('hidden', 'false').lower() == 'true'

        pconf = dict()
        pconf['hidden'] = hidden

        proc_wlist_string = lconf.get(constants.PROCESS_WHITE_LIST, None)
        if not proc_wlist_string is None:
            proc_wlist = [proc.strip() for proc in proc_wlist_string.split(',')]
            pconf[constants.PROCESS_WHITE_LIST] = proc_wlist
        else:
            proc_wlist = list()

        proc_blist_string = lconf.get(constants.PROCESS_BLACK_LIST, None)
        if not proc_wlist_string is None:
            proc_blist = [proc.strip() for proc in proc_blist_string.split(',')]
            pconf[constants.PROCESS_BLACK_LIST] = proc_blist
        else:
            proc_blist = list()

        if len(proc_wlist) > 0 and len(proc_blist) > 0:
            err = "Bad %s listener config: " % (lname,)
            err+= "Process whitelist and blacklist are mutually exclusive"
            logger.error(err)
            return None
        
        host_wlist_string = lconf.get(constants.HOST_WHITE_LIST, None)
        if not host_wlist_string is None:
            host_wlist = [host.strip() for host in host_wlist_string.split(',')]
            pconf[constants.HOST_WHITE_LIST] = host_wlist
        else:
            host_wlist = list()
    
        host_blist_string = lconf.get(constants.HOST_BLACK_LIST, None)
        if not host_blist_string is None:
            host_blist = [host.strip() for host in host_blist_string.split(',')]
            pconf[constants.HOST_BLACK_LIST] = host_blist
        else:
            host_blist = None
        
        if len(host_wlist) > 0 and len(host_blist) > 0:
            err = "Bad %s listener config: " % (lname,)
            err+= "Host whitelist and blacklist are mutually exclusive"
            logger.error(err)
            return None
        
        pconf[constants.EXECUTE_COMMAND] = lconf.get(constants.EXECUTE_COMMAND, None)
    
    return result