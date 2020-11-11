Development Suspended
=====================

The FLARE Team must suspend development and maintenance of FakeNet-NG for the
time being.

FLARE has opted to indicate the project status here instead of archiving the
project. This will allow users and maintainers to continue to log issues
documenting valuable information about problems, troubleshooting, and
work-arounds.

Original Documentation Follows
==============================
     ______      _  ________ _   _ ______ _______     _   _  _____
    |  ____/\   | |/ /  ____| \ | |  ____|__   __|   | \ | |/ ____|
    | |__ /  \  | ' /| |__  |  \| | |__     | |______|  \| | |  __
    |  __/ /\ \ |  < |  __| | . ` |  __|    | |______| . ` | | |_ |
    | | / ____ \| . \| |____| |\  | |____   | |      | |\  | |__| |
    |_|/_/    \_\_|\_\______|_| \_|______|  |_|      |_| \_|\_____|

           D   O   C   U   M   E   N   T   A   T   I   O   N

FakeNet-NG is a next generation dynamic network analysis tool for malware
analysts and penetration testers. It is open source and designed for the latest
versions of Windows (and Linux, for certain modes of operation). FakeNet-NG is
based on the excellent Fakenet tool developed by Andrew Honig and Michael
Sikorski.

The tool allows you to intercept and redirect all or specific network traffic
while simulating legitimate network services. Using FakeNet-NG, malware analysts
can quickly identify malware's functionality and capture network signatures.
Penetration testers and bug hunters will find FakeNet-NG's configurable
interception engine and modular framework highly useful when testing
application's specific functionality and prototyping PoCs.

Installation
============

You can install FakeNet-NG in a few different ways.

Stand-alone executable
----------------------

It is easiest to simply download the compiled version which can be obtained from
the releases page:

    https://github.com/fireeye/flare-fakenet-ng/releases

Execute FakeNet-NG by running 'fakenet.exe'.

This is the preferred method for using FakeNet-NG on Windows as it does not
require you to install any additional modules, which is ideal for a malware
analysis machine.

Installing module
-----------------

Installation on Windows requires the following dependency:
 * [Microsoft Visual C++ Compiler for Python 2.7](https://aka.ms/vcpython27)

Installation on Linux requires the following dependencies:
 * Python pip package manager (e.g. python-pip for Ubuntu).
 * Python development files (e.g. python-dev for Ubuntu).
 * OpenSSL development files (e.g. libssl-dev for Ubuntu).
 * libffi development files (e.g. libffi-dev for Ubuntu).
 * libnetfilterqueue development files (e.g. libnetfilter-queue-dev for
   Ubuntu).

Install FakeNet-NG as a Python module using pip:

    pip install https://github.com/fireeye/flare-fakenet-ng/zipball/master

Or by obtaining the latest source code and installing it manually:

    git clone https://github.com/fireeye/flare-fakenet-ng/

Change directory to the downloaded flare-fakenet-ng and run:

    python setup.py install

Execute FakeNet-NG by running 'fakenet' in any directory.

No installation
---------------

Finally if you would like to avoid installing FakeNet-NG and just want to run it
as-is (e.g. for development), then you would need to obtain the source code and
install dependencies as follows:

1) Install 64-bit or 32-bit Python 2.7.x for the 64-bit or 32-bit versions
   of Windows respectively.

2) Install Python dependencies:

    pip install pydivert dnslib dpkt pyopenssl pyftpdlib netifaces

   *NOTE*: pydivert will also download and install WinDivert library and
   driver in the `%PYTHONHOME%\DLLs` directory. FakeNet-NG bundles those
   files so they are not necessary for normal use.

2b) Optionally, you can install the following module used for testing:

    pip install requests

3) Download the FakeNet-NG source code:

    git clone https://github.com/fireeye/flare-fakenet-ng

Execute FakeNet-NG by running it with a Python interpreter in a privileged
shell:

    python fakenet.py

Usage
=====

The easiest way to run FakeNet-NG is to simply execute the provided
executable as an Administrator. You can provide `--help` command-line
parameter to get simple help:

    C:\tools\fakenet-ng>fakenet.exe --help
      ______      _  ________ _   _ ______ _______     _   _  _____
     |  ____/\   | |/ /  ____| \ | |  ____|__   __|   | \ | |/ ____|
     | |__ /  \  | ' /| |__  |  \| | |__     | |______|  \| | |  __
     |  __/ /\ \ |  < |  __| | . ` |  __|    | |______| . ` | | |_ |
     | | / ____ \| . \| |____| |\  | |____   | |      | |\  | |__| |
     |_|/_/    \_\_|\_\______|_| \_|______|  |_|      |_| \_|\_____|

                             Version  1.0
      _____________________________________________________________
                       Developed by FLARE Team
      _____________________________________________________________
    Usage: fakenet.py [options]:

    Options:
      -h, --help            show this help message and exit
      -c FILE, --config-file=FILE
                            configuration filename
      -v, --verbose         print more verbose messages.
      -l LOG_FILE, --log-file=LOG_FILE

As you can see from the simple help above it is possible to configure the
configuration file used to start FakeNet-NG. By default, the tool uses
`configs\default.ini`; however, it can be changed with the `-c` parameter.
There are several example configuration files in the `configs` directory.
Due to the large number of different settings, FakeNet-NG relies on the
configuration files to control its functionality.

NOTE: FakeNet-NG will attempt to locate the specified configuration file, first
by using the provided absolute or relative path in case you want to store all of
your configurations. If the specified configuration file is not found,
then it will try to look in its `configs` directory.

The rest of the command-line options allow you to control the amount
of logging output displayed as well as redirecting it to a file as
opposed to dumping it on the screen.

Simple run
----------

Before we dive in and run FakeNet-NG let's go over a few basic concepts. The
tool consists of several modules working together. One such important module is
the Diverter which is responsible for redirecting traffic to a collection of
listeners. The Diverter forces applications to interact with FakeNet-NG as
opposed to real servers. Listeners are individual services handling incoming
connections and allowing us to examine application's traffic (e.g. malware
signatures).

Let's launch FakeNet-NG using default settings by running the following command:

    C:\tools\fakenet-ng>fakenet.exe

Below is the annotated output log illustrating a sample intercepted DNS request
and an HTTP connection:

      ______      _  ________ _   _ ______ _______     _   _  _____
     |  ____/\   | |/ /  ____| \ | |  ____|__   __|   | \ | |/ ____|
     | |__ /  \  | ' /| |__  |  \| | |__     | |______|  \| | |  __
     |  __/ /\ \ |  < |  __| | . ` |  __|    | |______| . ` | | |_ |
     | | / ____ \| . \| |____| |\  | |____   | |      | |\  | |__| |
     |_|/_/    \_\_|\_\______|_| \_|______|  |_|      |_| \_|\_____|

                             Version  1.0
      _____________________________________________________________
                       Developed by FLARE Team
      _____________________________________________________________

    07/06/16 10:20:52 PM [           FakeNet] Loaded configuration file: configs/default.ini
                                                                            /
                                                default configuration file /

    07/06/16 10:20:52 PM [          Diverter] Capturing traffic to packets_20160706_222052.pcap
                                                                            /
                                                          PCAP output file /

    07/06/16 10:20:52 PM [           FakeNet] Anonymous Forwarder listener on TCP port 8080...
                                        \
                                         \ Anonymous Listener rule

    07/06/16 10:20:52 PM [    RawTCPListener] Starting...
    07/06/16 10:20:52 PM [    RawUDPListener] Starting...
    07/06/16 10:20:52 PM [  FilteredListener] Starting...
    07/06/16 10:20:52 PM [        DNS Server] Starting...
    07/06/16 10:20:52 PM [    HTTPListener80] Starting...
    07/06/16 10:20:52 PM [   HTTPListener443] Starting...
    07/06/16 10:20:52 PM [      SMTPListener] Starting...
    07/06/16 10:20:52 PM [          Diverter] Starting...
                                           \
                                            \ Listeners starting up

    07/06/16 10:20:52 PM [          Diverter] Diverting ports:
    07/06/16 10:20:52 PM [          Diverter] TCP: 1337, 80, 443, 25
    07/06/16 10:20:52 PM [          Diverter] UDP: 1337, 53
                                              /
                   Summary of diverted ports /

    07/06/16 10:21:03 PM [          Diverter] Modifying outbound external UDP request packet:
    07/06/16 10:21:03 PM [          Diverter]   from: 192.168.250.140:49383 -> 4.2.2.1:53
    07/06/16 10:21:03 PM [          Diverter]   to:   192.168.250.140:49383 -> 192.168.250.140:53
    07/06/16 10:21:03 PM [          Diverter]   pid:  456 name: malware.exe
                                                                /
        Intercepted traffic to the DNS server from malware.exe /

    07/06/16 10:21:03 PM [        DNS Server] Received A request for domain 'evil.com'.
                                           \
                                            \ Fake DNS Listener handling the above request

    07/06/16 10:21:04 PM [          Diverter] Modifying outbound external TCP request packet:
    07/06/16 10:21:04 PM [          Diverter]   from: 192.168.250.140:2179 -> 192.0.2.123:80
    07/06/16 10:21:04 PM [          Diverter]   to:   192.168.250.140:2179 -> 192.168.250.140:80
    07/06/16 10:21:04 PM [          Diverter]   pid:  456 name: malware.exe
                                                                /
        Intercepted traffic to the web server from malware.exe /

    07/06/16 10:21:08 PM [    HTTPListener80] Received a GET request.
    07/06/16 10:21:08 PM [    HTTPListener80] --------------------------------------------------------------------------------
    07/06/16 10:21:08 PM [    HTTPListener80] GET / HTTP/1.0
    07/06/16 10:21:08 PM [    HTTPListener80]
    07/06/16 10:21:08 PM [    HTTPListener80] --------------------------------------------------------------------------------
                                           \
                                            \ Fake HTTP Listener handling the above request

Notice that each log line has a name of the currently running FakeNet-NG
modules. For example, when it is diverting traffic, the logs will be prefixed
with the `Diverter` label:

    07/06/16 10:21:03 PM [          Diverter] Modifying outbound external UDP request packet:
    07/06/16 10:21:03 PM [          Diverter]   from: 192.168.250.140:49383 -> 4.2.2.1:53
    07/06/16 10:21:03 PM [          Diverter]   to:   192.168.250.140:49383 -> 192.168.250.140:53
    07/06/16 10:21:03 PM [          Diverter]   pid:  456 name: malware.exe

At the same time, whenever individual listeners are handling diverted traffic,
logs will be labeled with the name set in the configuration file:

    07/06/16 10:21:03 PM [        DNS Server] Received A request for domain 'evil.com'.

To stop FakeNet-NG and close out the generated PCAP file simply press `CTRL-C`:

    07/06/16 10:21:41 PM [           FakeNet] Stopping...
    07/06/16 10:21:42 PM [    HTTPListener80] Stopping...
    07/06/16 10:21:42 PM [   HTTPListener443] Stopping...
    07/06/16 10:21:42 PM [      SMTPListener] Stopping...
    07/06/16 10:21:43 PM [          Diverter] Stopping...

Configuration
-------------

In order to take full advantage of FakeNet-NG's capabilities we must understand
its configuration file structure and settings. Below is a sample configuration
file:

    ###############################################################################
    # Fakenet Configuration

    [FakeNet]

    DivertTraffic: Yes

    ###############################################################################
    # Diverter Configuration

    [Diverter]

    NetworkMode:            Auto

    LinuxRedirectNonlocal:  *
    LinuxFlushIptables:     Yes
    LinuxFlushDNSCommand:   service dns-clean restart

    DumpPackets:            Yes
    DumpPacketsFilePrefix:  packets

    ModifyLocalDNS:         No
    StopDNSService:         Yes

    RedirectAllTraffic:     Yes
    DefaultTCPListener:     RawTCPListener
    DefaultUDPListener:     RawUDPListener

    ###############################################################################
    # Listener Configuration

    [DNS Server]
    Enabled:     True
    Port:        53
    Protocol:    UDP
    Listener:    DNSListener
    DNSResponse: 192.0.2.123
    NXDomains:   0
    Hidden:      False

    [RawTCPListener]
    Enabled:     True
    Port:        1337
    Protocol:    TCP
    Listener:    RawListener
    UseSSL:      No
    Timeout:     10
    Hidden:      False

The configuration file is broken up into several sections.

* **[FakeNet]** - Controls the behavior of the application itself. The only valid
option at this point is `DivertTraffic`. When enabled, it instructs the tool
to launch the appropriate Diverter plugin and intercept traffic. If this option
is disabled, FakeNet-NG will still launch listeners, but will rely on another
method to direct traffic to them (e.g. manually change DNS server).

* **[Diverter]** - Settings for redirecting traffic. Covered in detail below.

* **[Listener Name]** - A collection of listener configurations. Each listener
has a set of default settings (e.g. port, protocol) as well as listener
specific configurations (e.g. DumpHTTPPosts for the HTTPListener).

Diverter Configuration
----------------------

Supposing you have enabled the `DivertTraffic` setting in the `[FakeNet]`
configuration block, the tool will enable its traffic redirection engine to
which we will call Diverter from now on as a reference to the excellent
`WinDivert` library used to perform the magic behind the scenes on Windows
platforms (the Linux implementation of the Diverter uses
[python-netfilterqueue](https://github.com/kti/python-netfilterqueue/)).

The Diverter will examine all of the outgoing packets and match them against
a list of protocols and ports of enabled listeners. If there is a listener
listening on the packet's port and protocol, then the destination address
will be changed to the local machine's IP address where the listener will
handle the request. At the same time, responses coming from the listener
will be changed so that the source IP address would appear as if the packet
is coming from the originally requested host.

You can optionally enable the `DumpPackets` setting to store all traffic
observed by FakeNet-NG (redirected or forwarded) to a PCAP file. It is possible
to decrypt SSL traffic between an intercepted application and one of the
listeners with SSL support. Use the instructions at the following page:

    https://wiki.wireshark.org/SSL

The keys `privkey.pem` and `server.pem` used by FakeNet-NG's servers are in the
application's root directory.

* **NetworkMode** - Specify the network mode in which to run FakeNet-NG.
    * Valid settings are:
        * `SingleHost`: manipulate traffic from local processes.
        * `MultiHost`: manipulate traffic from other systems.
        * `Auto`: use whatever `NetworkMode` is most functional on the current
          platform.
    * Not all platforms currently support all `NetworkMode` settings. Here is
      the current status of support:
        * Windows supports only `SingleHost`
        * Linux supports `MultiHost` and experimentally supports `SingleHost`
          mode (works with the exception of process, port, and host
          blacklisting and whitelisting).
    * For now, leave this set to `Auto`
          to get `SingleHost` mode on Windows and `MultiHost` mode on Linux.

The Diverter generally supports the following DNS-related setting:

* **ModifyLocalDNS** - point local machine's DNS service to FakeNet-NG's DNS
                       listener.

The Windows implementation of Diverter supports the following DNS-related
setting:

* **StopDNSService** - stops the Windows DNS client service (Dnscache). This
                       allows FakeNet-NG to see the actual processes resolving
                       domains as opposed to the generic 'svchost.exe' process.

The Linux implementation of Diverter supports the following settings:

* **LinuxRedirectNonlocal** - When using FakeNet-NG to simulate Internet
                              connectivity for a different host, this specifies
                              which externally facing network interfaces to
                              re-route to FakeNet-NG.
* **LinuxFlushIptables**    - Flush all `iptables` rules before adding rules
                              for FakeNet-NG. The Linux Diverter will restore
                              the old rules as long as its termination sequence
                              is not interrupted.
* **LinuxFlushDnsCommand**  - Specify the correct command for your Linux
                              distribution to flush the DNS resolver cache if
                              applicable.

* **DebugLevel**            - Specify fine-grained debug events to display.
                              Refer to [fakenet/diverters/linutil.py](fakenet/diverters/linutil.py)
                              for valid labels.

Redirecting All Traffic
-----------------------

By default the Diverter will only intercept traffic that has a dedicated
listener created for it. However, by enabling `RedirectAllTraffic` setting
and configuring the default TCP and UDP handlers with the `DefaultTCPListener`
and `DefaultUDPListener` settings it is possible to dynamically handle traffic
going to ports not explicitly defined in one of the listeners. For example,
let's look at a sample configuration which redirects all traffic to
local TCP and UDP listeners on ports 1234:

    RedirectAllTraffic: Yes
    DefaultTCPListener: TCPListener1234
    DefaultUDPListener: UDPListener1234

*NOTE*: We are jumping a bit ahead with listener definitions, but just
consider that `TCPListener1234` and `UDPListener1234` will be defined in
the section below.

With the `RedirectAllTraffic` setting, FakeNet-NG will modify not only the
destination address, but also the destination port so it can be handled
by one of the default listeners. Below is a sample log of traffic destined to
an external host IP address 1.1.1.1 on port 4444 which was redirected to the
default listener on port 1234 instead:

    07/06/16 01:13:47 AM [          Diverter] Modifying outbound external TCP request packet:
    07/06/16 01:13:47 AM [          Diverter]   from: 192.168.66.129:1650 -> 1.1.1.1:4444
    07/06/16 01:13:47 AM [          Diverter]   to:   192.168.66.129:1650 -> 192.168.66.129:1234
    07/06/16 01:13:47 AM [          Diverter]   pid:  3716 name: malware.exe

It is important to note that traffic destined to the port from one of the
explicitly defined listeners will still be handled by that listener and
not the default listener. For example, default UDP listener will not handle
DNS traffic if a separate UDP port 53 DNS listener is defined.

One issue when enabling the `RedirectAllTraffic` options is that you may
still want to let some traffic through to ensure normal operation of the
machine. Consider a scenario where you are trying to analyze an application
 that still needs to connect to an external DNS server. You can utilize the
`BlackListPortsTCP` and `BlackListPortsUDP` settings to define a list of
ports to which traffic will be ignored and forwarded unaltered:

    BlackListPortsUDP: 53

Some other Diverter settings that you may consider are `ProcessBlackList`
and `HostBlackList` which allow Diverter to ignore and forward traffic
coming from a specific process name or destined for a specific host
respectively.

Listener Configurations
----------------------

Listener configurations define the behavior of individual listeners. Let's
look at a sample listener configuration:

    [TCPListener1234]
    Enabled:     True
    Port:        1234
    Protocol:    TCP
    Listener:    RawListener
    UseSSL:      Yes
    Timeout:     10
    Hidden:      False

The configuration above consists of the listener name `TCPListener1234`. It
will be used for logging purposes so you can distinguish between different
listeners handling connections even if they are handling the same protocol.

The following settings are generic for all listeners:

 * **Enabled**          - specify whether or not the listener is enabled.
 * **Port**             - TCP or UDP port to listen on.
 * **Protocol**         - TCP or UDP
 * **Listener**         - Listener name to handle traffic.
 * **ProcessWhiteList** - Only traffic from these processes will be modified
                      and the rest will simply be forwarded.
 * **ProcessBlackList** - Traffic from all but these processes will be simply
                      forwarded and the rest will be modified as needed.
 * **HostWhiteList**    - Only traffic to these hosts will be modified and
                      the rest will be simply forwarded.
 * **HostBlackList**    - Traffic to these hosts will be simply forwarded
                      and the rest will be modified as needed.
 * **ExecuteCmd**       - Execute command on the first connection packet. This
                      feature is useful for extending FakeNet-NG's functionality
                      (e.g. launch a debugger on the connecting pid to help with
                      unpacking and decoding.)
 * **Hidden**           - Do not allow traffic to be directed to this listener
                      without going through the proxy which will determine the
                      protocol based on the packet contents

The `Port` and `Protocol` settings are necessary for the listeners to know to
which ports to bind and, if they support multiple protocol (e.g RawListener),
decide which protocol to use. They are also used by the Diverter to figure out
which ports and protocols to redirect.

The `Listener` setting defines one of the available listener plugins to handle
redirected traffic. The current version of FakeNet-NG comes with the following
listeners:

* **DNSListener**  - supports DNS protocol and replies to A records with either
                 a local machine's IP address or a configurable address in
                 the `DNSResponse` setting. You can also set the `NXDomains`
                 attribute to the number of requests the listener should ignore.
                 This way you may be able to get the malware to request all of
                 its backup C2 controller names. The listener supports both TCP
                 and UDP protocols.
* **RawListener**  - supports basic TCP and UDP binary protocols. The default
                 behavior is to simply echo the received packets back to
                 the client. Supports SSL connections.
* **HTTPListener** - supports HTTP and HTTPS protocols. Responds with different
                 files in the configurable `Webroot` directory based on the
                 requested file extension. Optionally dumps POST requests to
                 a configurable file which can be specified using
                 `DumpHTTPPosts` and `DumpHTTPPostsFilePrefix` settings.
* **SMTPListener** - supports SMTP protocol.
* **ProxyListener**- Detects protocol based on packet contents and redirects
                 packets accordingly.


NOTE: FakeNet-NG will attempt to locate the webroot directory, first by using
the provided absolute or relative paths. If the specified webroot path is not
found, then it will try to look in its `defaultFiles` directory.

As a special case, the Windows Diverter implementation automatically responds
to all ICMP requests while running. So in case a malware attempts to ping a
host to test connectivity it will get a valid response. The Linux Diverter
logs and forwards all ICMP packets to localhost.

NOTE: Some listeners can handle file uploads (e.g. TFTPListener and BITSListener).
All uploaded files will be stored in the current working directory with a
configurable prefix (e.g. "tftp_" for TFTP uploads).

Listener Filtering
------------------

FakeNet-NG supports several filtering rules consisting of process and host
blacklists and whitelists. The whitelists are treated as the rules that allow
connections to the listeners while the blacklists are used to ignore the
incoming connections and let them to be simply forwarded.

For example, consider the configuration below with process and host filters:

    [FilteredListener]
    Enabled:     True
    Port:        31337
    Protocol:    TCP
    Listener:    RawListener
    UseSSL:      No
    Timeout:     10
    ProcessWhiteList: malware.exe, ncat.exe
    HostBlackList: 5.5.5.5

The `FilteredListener` above will only handle connection coming from the
processes `malware.exe` and `ncat.exe`, but will ignore any connections
destined for the host `5.5.5.5`. Meaning that if a process called `test.exe`
attempted to connect on port 31337 it will not be redirected to the listener
and will be forwarded to wherever it was originally intended if the route
is available.

At the same time of the process `malware.exe` attempted to connect to port 31337
on any host other than `5.5.5.5` it will be diverted
to the `FilteredListener`. Any connections from the process `malware.exe`
destined to `5.5.5.5` would be allowed through.

Listener Command Execution
--------------------------

Another powerful configuration setting is `ExecuteCmd`. It essentially
allows you to execute an arbitrary command on the first detected packet
of the connection. The value of `ExecuteCmd` can use several format string
variables:

  * `{pid}`      - process id
  * `{procname}` - process executable name
  * `{src_addr}` - source address
  * `{src_port}` - source port
  * `{dst_addr}` - destination address
  * `{dst_port}` - destination port

Consider a scenario of a packed malware sample which connects to a configured
C2 server on port 8443 (Use `RedirectAllTraffic` if the port is not known). In
many cases the malware would unpack itself by the time it makes the connection
making that point in execution ideal to attach to the process with a debugger
and dump an unpacked version of it for further analysis.

Let's see how this can be used to automatically launch a debugger on the
first connection:

    [C2Listener]
    Enabled:     True
    Port:        8443
    Protocol:    TCP
    Listener:    RawListener
    UseSSL:      Yes
    Timeout:     300
    ProcessWhiteList: malware.exe
    ExecuteCmd:  C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe -p {pid}

Once FakeNet-NG detects a new connection coming from the whitelisted process
`malware.exe` (this setting is optional), it will automatically launch `windbg`
and attach it to the connecting process.

*NOTE*: You might want to extend the normal `Timeout` setting in case the malware
      needs to further interact with the listener.

Anonymous Listener
------------------

There is a special use case where you can create a new listener configuration
without defining the actual listener to handle it:

    [Forwarder]
    Enabled:     True
    Port:        8080
    Protocol:    TCP
    ProcessWhiteList: chrome.exe

Without a listener defined, FakeNet-NG will still divert traffic to the local
machine, but a separate listener must be launched by the user. For example,
you could have an HTTP proxy listening for connections on port 8080 and let
FakeNet-NG intercept all the traffic from applications which do not use system's
proxy server settings or use hard-coded IP addresses. Using anonymous listeners
you can bring FakeNet-NG's advanced traffic and process filtering capabilities
to 3rd party tools.

You may also want to enable Diverter's `ProcessBlackList` setting to allow
the external tool to communicate out to the Internet. For example, to allow
an HTTP proxy to forward proxied traffic add its process name to the process
blacklist. For example, add the following process to let Burp Proxy to
communicate out to the Internet:

    ProcessBlackList: java.exe

In the scenario where application communicates on an unknown port, but you still
want to redirect it to the anonymous listener on port 8080 you can define the
default listener as follows:

    RedirectAllTraffic: Yes
    DefaultTCPListener: ForwarderTCP
    DefaultUDPListener: RawUDPListener

Finally, to allow DNS traffic to still go to the default DNS server on the
Internet, while redirecting all other traffic, add port 53 to the Diverter's
UDP port blacklist as follows:

    BlackListPortsUDP:

Proxy Listener
--------------

The latest release of FakeNet-NG implements a new proxy listener which is capable of
dynamically detecting communicating protocol (including SSL traffic) and redirecting
the connecting to an appropriate listener.

You can configure the proxy listener to work on a specific port as illustrated in the
configuration below:

    [ProxyTCPListener]
    Enabled:    True
    Protocol:   TCP
    Listener:   ProxyListener
    Port:       38926
    Listeners:  HTTPListener, RawListener, FTPListener, DNSListener, POPListener, SMTPListener, TFTPListener, IRCListener, BITSListener
    Hidden:     False

Note, the new `Listeners` parameter which defines a list of potential protocol handlers
to try for all incoming connections.

It is also recommended to define a proxy listener as your default handler by updating
the following diverter configurations:

    RedirectAllTraffic:    Yes
    DefaultTCPListener:    ProxyTCPListener
    DefaultUDPListener:    ProxyUDPListener

With the default listener pointing to the proxy listener, all unknown connections
will be appropriately handled. You can still assign specific listeners to ports to
enforce a specific protocol (e.g. always use HTTP listener for port 80).

The Proxy determines the protocol of packets by polling all available listeners with
the function taste(). Each Listener that implements taste() will respond with a score
indicating the likelihood that the protocol handled by that listener matches the
packet contents. The Proxy will forward the packet to the Listener that returned the
highest score. The RawListener will always return a score of 1, so it will be chosen
in the case that all other Listeners return 0, thus serving as the default.

Users can alter the configuration parameter 'Hidden' in each Listener's configuration.
If Hidden is 'False', the Listener will be bound to a specific port and automatically
receive all traffic on that port. With Hidden set to 'True', the Listener can only
receive traffic that is redirected through the Proxy.

Development
===========

FakeNet-NG is developed in Python which allows you to rapidly develop new
plugins and extend existing functionality. For details, see
[Developing for FakeNet-NG](docs/developing.md).

Known Issues
============

Does not work on VMWare with host-only mode enabled
---------------------------------------------------

See "Not Intercepting Traffic" below.

Not Intercepting Traffic
------------------------

In order to for FakeNet-NG to intercept and modify the packet, there must exist
a valid network route for the packet to reach its destination.

There is an easy way to check whether or not you have routes set up correctly.
Without the tool running attempt to ping the destination host. You should
observe either a valid response or a timeout message. If you receive a
destination not reachable error instead, then you do not have a valid route.

This is usually caused by your gateway being either not set or not reachable.
For example, on a VMWare machine with host-only mode your machine will not have
the gateway configured thus preventing FakeNet-NG from seeing any traffic.

To correct this issue, manually configure your primary interface to the gateway
in the same subnet. First check the interface name:

    C:\>netsh interface show interface

    Admin State    State          Type             Interface Name
    -------------------------------------------------------------------------
    Enabled        Connected      Dedicated        Local Area Connection

In this case the interface name is "Local Area Connection" so we will use it for
the rest of the commands.

Manually configure the interface IP address and gateway as follows:

    C:\>netsh interface ip set address name="Local Area Connection" static 192.168.249.123 255.255.255.0 192.168.249.254

Manually set the DNS server IP address

    C:\>netsh interface ip set dns name="Local Area Connection" static 4.2.2.2

If you are still having issue ensure that the gateway IP address itself is
routable.

DNS Not Resolving Names
-----------------------
Ensure that the DNS Listener successfully bound to its port. Errors such as the
following indicate that the DNS Listener did not successfully bind:

```
05/01/17 11:11:16 AM [           FakeNet] Error starting DNSListener listener:
05/01/17 11:11:16 AM [           FakeNet]  [Errno 98] Address already in use
```

Use `netstat`, `tcpview`, or other tools to discover what application is bound
to the port, and refer to the corresponding operating system or application
documentation to disable the service.

It may make sense to capture a VM snapshot before undertaking reconfiguration.

For example, Ubuntu commonly enables the `dnsmasq` service in
`/etc/NetworkManager/NetworkManager.conf` with the line `dns=dnsmasq`.
Disabling this (such as by commenting it out) and restarting the
`network-manager` service (e.g. `service network-manager restart`) is
sufficient to free the port before re-launching FakeNet-NG.

In newer versions of Ubuntu or in other distributions, using `lsof -i` may
reveal that `systemd-resolved` is used instead. In these cases, you may try
these steps adapted from
<https://askubuntu.com/questions/907246/how-to-disable-systemd-resolved-in-ubuntu>:

```
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
```

Then in `/etc/NetworkManager/NetworkManager.conf` under the `[main]` section, add a line specifying:

```
dns=default
```

Delete the symlink `/etc/resolv.conf`, i.e. `rm /etc/resolv.conf`.

Finally, restart `NetworkManager`:

```
sudo systemctl restart NetworkManager
```

Error: Could not locate WinDivert DLL or one of its components
--------------------------------------------------------------

Please ensure that FakeNet-NG is extracted to the local C: drive to make
sure the WinDivert driver is loaded correctly.

Error: The application has failed to start because its side-by-side configuration is incorrect.
-----------------------------------------------------------------------------------------------

This error may occur when running a stand-alone executable version of Fakenet. Please download and install Visual C++ 2008 runtime executable.

Limitations
===========

* Only Windows Vista+ is supported for `SingleHost` mode. Please use the
  original Fakenet for Windows XP/2003 operating systems.

* Only Linux is supported for `MultiHost` mode.

* Old versions of python-netfilterqueue can cause a segmentation fault in
  `python`. If you experience this issue, check that you are using the latest
  version of python-netfilterqueue.

* Due to the hard-coded buffer size used by python-netfilterqueue, the Linux
  Diverter does not correctly handle packets greater than 4,016 bytes in size.
  In practice, this does not affect Linux `MultiHost` mode for interfaces
  configured with the conventional 1,500 byte maximum transmittal unit (MTU).
  If the Linux interface you are using with FakeNet-NG supports an MTU greater
  than 4016, you will need to recompile python-netfilterqueue to support a
  buffer size of `<your_mtu> + 80` (python-netfilterqueue devotes 80 bytes of
  the buffer to overhead).

* Local machine only traffic is not intercepted on Windows (e.g. if you tried
  to connect directly to one of the listeners).

* Only traffic using TCP, UDP, and ICMP protocols is intercepted.

Credits
=======

* FakeNet-NG was designed and developed by Peter Kacherginsky.
* Special thanks to Andrew Honig, Michael Sikorski and others for the
  original FakeNet which was the inspiration to develop this tool.
* The Linux Diverter was designed and developed by Michael Bailey.
* Thanks to Matthew Haigh for developing the proxy protocol autodetection feature.
* Thanks to Cody Pierce and Antony Saba for reporting and fixing a
  file system traversal vulnerability.

Contact
=======

For bugs, crashes, or other comments please contact
FakeNet@fireeye.com.

