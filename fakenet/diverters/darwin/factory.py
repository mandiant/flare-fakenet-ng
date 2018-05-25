import logging
from diverters.darwin.kext import KextDiverter
from diverters.darwin.usermode import UsermodeDiverter


DIVERTER_MODE_KEY = 'darwindivertermode'
DIVERTER_MODE_USER = 'user'
DIVERTER_MODE_KERNEL = 'kernel'
DEFAULT_MODE = DIVERTER_MODE_USER


def make_diverter(dconf, lconf, ipaddrs, loglvl=logging.INFO):
    mode = dconf.get(DIVERTER_MODE_KEY, DEFAULT_MODE).lower()
    print dconf
    print mode
    if mode == DIVERTER_MODE_USER:
        diverter = UsermodeDiverter(dconf, lconf, ipaddrs, loglvl)
    elif mode == DIVERTER_MODE_KERNEL:
        diverter = KextDiverter(dconf, lconf, ipaddrs, loglvl)
    else:
        return None
    return diverter