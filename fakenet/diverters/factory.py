
def make_diverter(platform, diverter_config, listeners_config, ip_addrs, log_level):
    ctor = None
    if platform == 'linux':
        from diverters.linux import diverter as linux_diverter
        ctor = linux_diverter
    if ctor is None:
        return None

    return ctor(diverter_config, listeners_config, ip_addrs, log_level)
