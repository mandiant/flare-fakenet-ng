# FakeNet-NG Architecture
FakeNet-NG simulates the Internet by intercepting incoming and/or outgoing
packets on Windows and Linux through its Diverter component and sending them to
services called Listeners that are local to the FakeNet-NG host. In its default
configuration, the Diverter generally directs traffic to the ProxyListener.
The ProxyListener is a special Listener that implements a full-duplex proxy
capable of detecting and decoding SSL, previewing application-layer data, and
polling the other listeners to evaluate which one deems itself most likely to
be conversant in the protocol being used within a given connection. The other
Listeners (e.g. HTTP, FTP, SMTP) communicate with the end-client either
directly (if they are not hidden behind the ProxyListener) or through the
ProxyListener. This architecture is in contrast to tools like PyNetSim (can't
find an authoritative hyperlink to cite this reference) that effectively
integrate all services into a bus. The benefit of this additional complexity in
FakeNet-NG’s architecture is that it can incorporate Listeners based on generic
code that expects to directly bind to ports and manage its own sockets. The
FakeNet-NG architecture is diagrammed subsequently.

![FakeNet-NG Architecture](https://github.com/fireeye/flare-fakenet-ng/raw/master/docs/fakenet_architecture.png "FakeNet-NG Architecture")

# Diverters

## Diverter Base Class
The Diverters for both Windows and Linux derive from the `DiverterBase` class
(`fakenet/diverters/diverterbase.py`). It implements abstract processing for
reasoning over packets and determining whether to pass them, mangle (modify)
them, or drop them.

To derive from `DiverterBase`, the Diverters for both Windows and Linux each
must implement their own `startCallback` method to create threads on the system
that handle packets returned by their respective packet filtering library. In
those thread routines, the Windows and Linux Diverters each create a
`PacketCtx` (packet context) object (`fakenet/diverters/fnpacket.py`) and pass
it to `DiverterBase.handle_pkt` to perform pcap recording, determine whether
to NAT or port forward the packet, and rewrite the packet contents (including
checksum calculation). Upon completion of `handle_pkt`, child classes packet
filter thread routines must check if the packet must be modified through the
Boolean `PacketCtx.mangled` attribute, and if it is set, use their own
OS-specific code to write the contents of the updated `PacketCtx.octets`
attribute to the packet before allowing it to be transmitted.

Another condition of deriving from `DiverterBase` is to implement
`stopCallback` to reap packet filtering threads and return the system to its
original configuration.

Historically because of the number of Windows APIs that must be invoked
through Python `ctypes` in the Windows Diverter, the diverter was split into
two files. One file contained OS-specific `ctypes` wrappers and error
handling (`winutil.py`) and the other contained the core code of the Diverter
for that operating system (`windows.py`). The methods in the ancillary file
`winutil.py` became part of a mix-in class (`WinUtilMixin`) and also
contained OS-specific methods for handling things that needed to be done in a
Windows-specific way to start FakeNet, like checking for active ethernet
adapters.

The `DiverterPerOsDelegate` abstract base class
(`fakenet/diverters/diverterbase.py`) formalizes this dichotomy as a set of
additional methods that must be implemented by the Diverter for each platform.
In practice, both Linux and Windows Diverters implement an OS-specific mix-in
that fulfills the contract defined by this interface. The creation of the
`DiverterPerOsDelegate` was an exercise in documentation more than programming
or architecture. It moves toward formalizing the interface that previously
existed as an implicit dependency on these methods codified merely by calling
them from the `DiverterBase` constructor and expecting them to be implemented
in each child class.

## Windows Diverter
The Windows Diverter views and manipulates packets through PyDivert, which is a
Python binding for WinDivert. WinDivert comprises a userspace component and an
NDIS networking driver.

The Windows Diverter is implemented in the `Diverter` class in
`fakenet/diverters/windows.py`, which derives from `DiverterBase`
and implements the necessary `startCallback` and `stopCallback` methods. It
also inherits from `WinUtilMixin` from `fakenet/diverters/winutil.py` which
is the derived `DiverterPerOsDelegate` for Windows and implements selected
callbacks defined there to customize activities involving gateways, DNS, etc.

## Linux Diverter
The Linux Diverter views and manipulates packets through
`python-netfilterqueue`, which is a Cython wrapper for `libnetfilterqueue`.
`libnetfilterqueue` is the user-space native C library for interfacing with the
Linux NetFilter kernel framework.

The Linux Diverter is implemented in the `Diverter` class in
`fakenet/diverters/linux.py`, which derives from `DiverterBase` and
implements the necessary `startCallback` and `stopCallback` methods. It also
inherits from `LinUtilMixin` which is the derived `DiverterPerOsDelegate` for
Linux and implements selected callbacks defined there to customize activities
involving gateways, DNS, etc.

# ProxyListener
The ProxyListener is a full-duplex proxy implemented for both TCP and UDP. The
ProxyListener implements automatic SSL/TLS detection and content-sensitive
application-layer routing. It does this by sampling application-layer data to
determine if it must be wrapped with SSL. It then samples the application-layer
data again after wrapping with SSL (or uses the already-sampled data if SSL is
not needed) to pass to a callback in each listener to determine which listener
is the most appropriate for the traffic. Its configuration consequently entails
access to the implementations of the other listeners for purposes of calling
the `taste` callback in each listener to determine where to send the traffic.

# More Information
For a discussion of how FakeNet-NG's `DiverterBase` arrives at IP NAT
decisions, Dynamic Port Forwarding (DPF) decisions, and more, see
[FakeNet-NG Internals](internals.md).
