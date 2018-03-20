# Debug print levels for fine-grained debug trace output control
DNFQUEUE = (1 << 0)     # netfilterqueue
DGENPKT = (1 << 1)      # Generic packet handling
DGENPKTV = (1 << 2)     # Generic packet handling with TCP analysis
DCB = (1 << 3)          # Packet handlign callbacks
DPROCFS = (1 << 4)      # procfs
DIPTBLS = (1 << 5)      # iptables
DNONLOC = (1 << 6)      # Nonlocal-destined datagrams
DDPF = (1 << 7)         # DPF (Dynamic Port Forwarding)
DDPFV = (1 << 8)        # DPF (Dynamic Port Forwarding) Verbose
DIPNAT = (1 << 9)       # IP redirection for nonlocal-destined datagrams
DMANGLE = (1 << 10)     # Packet mangling
DPCAP = (1 << 11)       # Pcap write logic
DIGN = (1 << 12)        # Packet redirect ignore conditions
DFTP = (1 << 13)        # FTP checks
DMISC = (1 << 27)       # Miscellaneous

DCOMP = 0x0fffffff      # Component mask
DFLAG = 0xf0000000      # Flag mask
DEVERY = 0x0fffffff     # Log everything, low verbosity
DEVERY2 = 0x8fffffff    # Log everything, complete verbosity

DLABELS = {
    DNFQUEUE: 'NFQUEUE',
    DGENPKT: 'GENPKT',
    DGENPKTV: 'GENPKTV',
    DCB: 'CB',
    DPROCFS: 'PROCFS',
    DIPTBLS: 'IPTABLES',
    DNONLOC: 'NONLOC',
    DDPF: 'DPF',
    DDPFV: 'DPFV',
    DIPNAT: 'IPNAT',
    DMANGLE: 'MANGLE',
    DPCAP: 'PCAP',
    DIGN: 'IGN',
    DFTP: 'FTP',
    DIGN | DFTP: 'IGN-FTP',
    DMISC: 'MISC',
}

DLABELS_INV = {v.upper(): k for k, v in DLABELS.iteritems()}
