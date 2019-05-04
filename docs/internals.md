# FakeNet-NG Internals

This documentation was originally written for the Linux implementation, and
where specifics are called for, it currently references Linux.

## FakeNet-NG Diverter Internals

For purposes of this documentation, some rigorously-defined terms will be
repurposed or replaced:
* TCP defines an _endpoint_ to be a host address and a port number. Although
  the concept of an endpoint is specific to TCP, we will use the term loosely
  to mean a host address and port number for any transport protocol we know how
  to examine (i.e. both TCP and UDP).
* TCP defines a _connection_ as two endpoints. Because UDP is connectionless,
  we will use the more general term _conversation_ to represent the concept of
  a pair of endpoints (again, using that term loosely) that are communicating.

FakeNet-NG can also operate in two modes on Linux:
* `SingleHost` - simulate the Internet for the local machine
* `MultiHost` - simulate the Internet by acting as the gateway for another
  machine

Each implementation of FakeNet-NG ultimately relies on a driver or kernel
module that supports network hooking and a library that makes this accessible
from user space. The Windows Diverter uses
[PyDivert](https://github.com/ffalcinelli/pydivert) to control the
[WinDivert](https://reqrypt.org/windivert.html) driver. The Linux Diverter uses
[python-netfilterqueue](https://github.com/kti/python-netfilterqueue) to access
[libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue/) and in
turn [NetFilter](https://netfilter.org/).

### Traffic Flow Condition Evaluation

The simplest case for the Linux implementation of the FakeNet-NG Diverter is
`MultiHost` mode, because IP network address translation (NAT) is not required
to support any conditional evaluation such as process blacklists. Hence,
we use `iptables` to implement a `REDIRECT` rule in the `PREROUTING` chain.
This opportunistic preference for allowing the Linux kernel to perform NAT is
driven also by the expectation that the comprehensive heuristics in the
NetFilter `conntrack` module can do a better job of tracking and correctly
NATting traffic than the simple code in FakeNet. In this use case, FakeNet-NG
implements only dynamic port forwarding (DPF)
using python-netfilterqueue.

The more complicated case is `SingleHost` mode, in which both DPF and NAT must
be controlled by FakeNet-NG to permit process blacklisting and other
configuration settings. In this case, FakeNet-NG evaluates four conditions:

1. When a packet is produced, is it destined for a foreign IP address? (if so,
  fix up its destination address to be a local address)
2. When a packet is about to be consumed, is it destined for an unbound port?
  (if so, fix up its destination port to that of the default listener for this
  protocol)
3. When a reply packet is produced, is it part of a conversation that has been
  port-forwarded? (if so, fix up its source port)
4. When a reply packet is about to be consumed, is it part of a conversation
  that has been NATted? (if so, fix up its source IP)

Given two processes `P1` and `P2`, here is a diagram of communication and
condition evaluation specific to Linux, using the `INPUT` and `OUTPUT` chains
provided by Netfilter:

```
         (1)                                                      (2)
  .-> [ OUTPUT ] -> [ POSTROUTING ] -> N -> [ PREROUTING ] -> [ INPUT ] ---.
 |                                     E                                    |
 |                                     T                                    V
[P1]                                   W                                  [P2]
 A                                     O                                    |
 |                                     R                                    |
  '---[ INPUT ] <- [ PREROUTING ] <--- K <- [ POSTROUTING ] <- [ OUTPUT ]<-'
         (4)                                                      (3)
```

And here is more detail on how these conditions are evaluated, per hook:

* OUTPUT: Evaluate conditions (1) and (3):
	* For (1), check if the packet is destined for a non-local IP address
	  and if so, forward it to 127.0.0.1.
	* For (3), check if the packet's remote endpoint was port forwarded and
	  if so, fix up the source port to match the transport layer's
	  expectations.
* INPUT: Evaluate conditions (2) and (4):
	* For (2), check if the packet is destined for an unbound port and if
	  so, forward it to the default port.
	* For (4), check if the packet's remote endpoint has been IP forwarded
	  and if so, fix up the source IP address to match the transport
	  layer's expectations.

Conditions (3) and (4) are necessary to ensure that the transport layer
protocol stack perceives the packet as coming from the same endpoint (IP and
port) and continues the conversation instead of seeing an extraneous endpoint
and sending an RST.

### Explaining Hook Location Choices

#### Observing packets destined for non-local IP addresses

In `MultiHost` mode, when foreign packets come in having a non-local
destination IP, they have to be examined in the `PREROUTING` chain in order to
observe the non-local address before it is mangled into a local IP address by
the IP NAT (`PREROUTING`/`REDIRECT`) rule added by the `LinuxRedirectNonlocal`
configuration setting.

In contrast, when using FakeNet-NG under `SingleHost` mode, packets originated
by processes within the system that are destined for foreign IP addresses never
hit the `PREROUTING` chain, making this hook superfluous. That is why it is not
applied when FakeNet-NG is in SingleHost mode. Instead, the logging for IP
addresses having non-local destination IP addresses is performed within the
hook for outgoing packets.

#### Dynamic port forwarding in concert with IP NAT

In both `MultiHost` and `SingleHost` mode, FakeNet-NG implements dynamic port
forwarding (DPF) by mangling packets on their way in and out of the system.
Incoming packets destined for an unbound port are modified to point to a
default destination port and the packet checksums are recalculated. The remote
endpoint's IP address, protocol, and port are saved in a port forwarding lookup
table - much like Netfilter's NAT implementation that will be explained
subsequently - to be able to recognize outgoing reply packets and mangle them
to provide the illusion that the remote host is communicating with the port
that it asked for. If an outgoing packet's remote endpoint corresponds to a
port forwarding table entry, the source port is fixed up so that the remote TCP
stack does not perceive any issue with FakeNet-NG's replies.

Meanwhile, in `MultiHost` mode, FakeNet-NG relies on the kernel to implement IP
NAT via the iptables `REDIRECT` target. This works by using `conntrack` to
record tuples of information about packets going in one direction so that it
can recognize reply packets going in the opposite direction. By recording and
referring to this information, `conntrack` is able to correctly fix up the IP
addresses in reply packets. The `conntrack` module uses information like TCP
ports to recognize what packets need to be fixed up.  Therefore, it is
necessary to perform all DPF-related mangling of TCP ports on one side or the
other of the NAT so that `conntrack` symmetrically and uniformly observes
either client-side or DPF-mangled port numbers whenever it is calculating
tuples to determine a NAT match and mangle the packet to reflect the correct
source IP address. Incorrect chain/table placement of incoming and outgoing
packet hooks will result in IP NAT failing to recognize and fix up reply
packets. On the client side, this can be observed to manifest itself as (1) TCP
SYN/ACK packets coming from the FakeNet-NG host that do not mirror the
arbitrary IP addresses that the client is asking to talk to, and consequently
(2) TCP RST packets from the client due to the erroneous SYN/ACK responses it
is receiving (and consequently no three-way handshake, no TCP connection, and
no exchange of data).

Why not implement IP NAT ourselves? We are already using python-netfilterqueue
to manipulate and observe packet traversal. In `MultiHost` mode, we use
`conntrack` instead because it already handles protocols other than TCP/IP
(such as ICMP) and implements a rich library of protocol modules for reaching
above the network layer to accurately recognize connections for protocols such
as IRC, FTP, etc. We're not going to do a better job than that, and we don't
want to reinvent the wheel if we can avoid it. That being said, we do implement
our own NAT for `SingleHost` mode to support blacklisting and other features.

Given how the kernel's NAT implementation relies on `conntrack` being able to
see uniformly mangled or un-mangled ports in order to recognize and correctly
NAT communications, following are the locations where it is okay to place the
incoming and outgoing packet hook pairs for DPF so that we don't disrupt
`conntrack`'s ability to perform NAT for us:

```
        Incoming                          Outgoing
Chain             Tables          Chain           Tables
---------------------------------------------------------------------
`PREROUTING`      `raw`           `OUTPUT`        `mangle`, `nat`, `filter`
                                  `POSTROUTING`   (any)

`INPUT`           (any)           `OUTPUT`        `raw`
```

A handy graphic depicting Netfilter chains and tables in detail can be found
at:

https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg

Code relating to NAT redirection and connection tracking can be found in the
Linux kernel in the following files/functions (both IPv4 and IPv6 information
are available but only IPv4 is mentioned here):
* `net/netfilter/xt_REDIRECT.c`: `redirect_tg4()`
* `net/netfilter/nf_nat_redirect.c`: `nf_nat_redirect_ipv4()`
* `net/netfilter/nf_nat_core.c`: `nf_nat_setup_info()`

Documentation relating to NAT redirection and connection tracking can be found
at:

https://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-4.html#toc4.4

### Linux Diverter Composition

The Linux Diverter creates `LinuxDiverterNfqueue` objects within its `start()`
method to connect iptables `NFQUEUE` rules to Python hook functions. Each hook
function creates a `PacketHandler` object when a packet is received and calls
its `handle_pkt()` method. The `PacketHandler` object performs standard pre-
and post-callback packet processing (like extracting the IP version and next
protocol number), and provides a standard set of information to the network and
transport layer callbacks that perform the real work. More details follow.

The Linux Diverter implementation comprises the following classes:
* `DiverterBase` (`diverters/diverterbase.py`) - will facilitate a common
  interface (and ancestry) for refactoring of common code between Windows,
  Linux, and any other future Diverter implementations.
* `LinUtilMixin` (`diverters/linutil.py`) - handles most Linux-specific details
* `Diverter` (`diverters/linux.py`) - Inherits from `DiverterBase` and
  `LinUtilMixin`, implements packet handling logic for Linux.

The Linux Diverter uses the following helper classes:
* `IptCmdTemplate` (`diverters/linutil.py`) - standardizes, centralizes, and
  de-duplicates code used frequently throughout the Linux Diverter to construct
  and execute iptables command lines to add (`-I` or `-A`) and remove (`-D`)
  rules. `Diverter` and `LinuxDiverterNfqueue` use this.
* `LinuxDiverterNfqueue` (`diverters/linutil.py`) - handles iptables `NFQUEUE`
  rule addition/removal (through the `IptCmdTemplate` class), NetfilterQueue
  management, netlink socket timeout setup for threaded operation, thread
  startup, and monitoring for asynchronous stop requests.
* `ProcfsReader` (`diverters/linutil.py`) - Standard row and field reading for
  proc files. The Python procfs module is a really neat way to access procfs,
  But it doesn't seem to handle `/proc/net/netfilter/nfnetlink_queue`, and it
  seems like it might handle a file with only a header row (and no data rows)
  differently than a file that has data.

### Deciding Whether to Port Forward

Port forwarding decisions are made by a minimal sum-of-products (SOP) logic
function synthesized as follows.

A truth table was used to define the cases in which a port forwarding decision
would need to be made and the desired outcomes.

Truth table key:
* src - source IP address
* sport - source port
* dst - destination IP address
* dport - destination port
* lsrc - src is local
* ldst - dst is local
* bsport - sport is in the set of ports bound by FakeNet-NG listeners
* bdport - dport is in the set of ports bound by FakeNet-NG listeners
* R? - Redirect?
* m - Minterm (R? == 1)

```
Short names for convenience --> A       B       C       D       R
src     sport   dst     dport   lsrc    ldst    bsport  dsport  R?  m
-----------------------------------------------------------------------
Foreign Unbound Foreign Unbound 0       0       0       0       1   *
Foreign Unbound Foreign Bound   0       0       0       0       0
Foreign Bound   Foreign Unbound 0       0       0       0       1   *
Foreign Bound   Foreign Bound   0       0       0       0       0
Foreign Unbound Local   Unbound 0       0       0       0       1   *
Foreign Unbound Local   Bound   0       0       0       0       0
Foreign Bound   Local   Unbound 0       0       0       0       1   *
Foreign Bound   Local   Bound   0       0       0       0       0

(Rationale: When a foreign host is trying to talk to us or anyone else
in MultiHost mode, ensure unbound ports get redirected to a listener)

Local   Unbound Foreign Unbound 0       0       0       0       1   *
Local   Unbound Foreign Bound   0       0       0       0       0
Local   Bound   Foreign Unbound 0       0       0       0       0
Local   Bound   Foreign Bound   0       0       0       0       0
Local   Unbound Local   Unbound 0       0       0       0       1   *
Local   Unbound Local   Bound   0       0       0       0       0
Local   Bound   Local   Unbound 0       0       0       0       0
Local   Bound   Local   Bound   0       0       0       0       0

(Rationale: In SingleHost mode, the local machine will wind up talking
to itself if it tries to get out to a foreign IP. When the local
machine is talking to itself in SingleHost mode, ensure unbound
destination ports are redirected /except/ when the packet originates
from a bound port. )
```

To synthesize a minimal SOP function for this decision, we fed the minterms of
the above truth table (highlighted with asterisks) into the following Karnaugh
map (zeroes omitted for readability):

```
       CD
   AB \  00   01   11   10
       +-------------------.
    00 |  1 |    |    |  1 |
       +----+----+----+----+ -> A'D'
    01 |  1 |    |    |  1 |
       +----+----+----+----+
    11 |  1 |    |    |    |
       +----+----+----+----+
    10 |  1 |    |    |    |
       +----+----+----+----+
         |
         V
        C'D'
```

The resulting minimal SOP logic function was: `R(A, B, C, D) = A'D' + C'D'`

Or, in Python:

```python
        return ((not src_local and not dport_bound) or
				(not sport_bound and not dport_bound))
```

### Future

#### NetworkMode Auto for Linux
To implement an Auto mode for Linux that transparently handles both foreign and
local requests, we might consider using the `PREROUTING` chain to record source
endpoint information for all foreign packets and then checking incoming and
outgoing packets against this. That check could replace the current
`single_host_mode` Boolean instance variable allowing for each packet to be
correctly treated according to whether the conversation was initiated by a
foreign host. Linux Diverter initialization would have to be modified to
install all hooks and transport/network layer callbacks which would in turn
need to be adjusted to incorporate the logic described above to correctly opt
to handle (or not to handle) each packet.

##### python-netfilterqueue Fixed Buffer Size Workaround

python-netfilterqueue uses a fixed buffer size of 4096 resulting in issues
getting and setting payloads for packets exceeding 4016 bytes in size (the
buffer includes 80 bytes of overhead data). This issue was discovered when
troubleshooting problems transferring the 24KB file `FakeNet.gif` over FTP.

This is fine for `MultiHost` mode because external interfaces (e.g. `eth0`)
frequently have a maximum transmittal unit (MTU) of 1500. However, for loopback
communications where the MTU may be something like 65536, this causes errors.
It is possible to fix these errors by changing the buffer size to 65616
(accounting for 80 bytes of overhead), however this could be overridden by
future installations of python-netfilterqueue either via the package management
system specific to the Linux distribution, Pip, etc.

A work-around for this issue is to send all NAT packets through an externally
facing IP address instead of 127.0.0.1 to avoid exposing traffic to `BufferSize
< MTU` conditions such as in the transfer of large files.
