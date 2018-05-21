
import netifaces
import subprocess as sp

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


