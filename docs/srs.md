[//]: # (---------------------------------------------------------------------)
[//]: # (This is a comment. Comments are encoded as described here:           )
[//]: # (https://stackoverflow.com/questions/4823468/comments-in-markdown     )
[//]: # (Comments are used primarily to create section breaks for use in      )
[//]: # (navigating the raw markdown during editing.                          )
[//]: # (---------------------------------------------------------------------)

# FakeNet-NG Software Requirements Specification (SRS)
This specification describes FakeNet-NG, FLARE's next-generation dynamic
network analysis tool. This is largely based on the development that has taken
place to date and is a work in progress.

This document carries a little baggage with it to aid the uninitiated. For the
meat and bones of it, visit the `Functional Specification` top-level heading.

## Introduction
FakeNet-NG is a tool to aid in dynamic analysis of software, and is
specifically intended for analyzing malicious software. It is the Python-based
successor to the legacy
[`FakeNet`](https://practicalmalwareanalysis.com/fakenet/) native binary that
was introduced with the book [Practical Malware
Analysis](https://nostarch.com/malware).

## History
FakeNet-NG was initially released August 3, 2016 by Peter Kacherginsky with
support for Windows: [FakeNet-NG: Next Generation Dynamic Network Analysis
Tool](https://www.fireeye.com/blog/threat-research/2016/08/fakenet-ng_next_gen.html).

On July 5, 2017 FakeNet-NG was updated by Michael Bailey to add support for
Linux: [Introducing Linux Support for FakeNet-NG: FLARE's Next Generation
Dynamic Network Analysis
Tool](https://www.fireeye.com/blog/threat-research/2017/07/linux-support-for-fakenet-ng.html).

The next significant FakeNet-NG release was by Matthew Haigh on October 23,
2017 to introduce a proxy listener to sample, identify, and route traffic to
the most appropriate listener: [New FakeNet-NG Feature: Content-Based Protocol
Detection](https://www.fireeye.com/blog/threat-research/2017/10/fakenet-content-based-protocol-detection.html).

FireEye's [flare-fakenet-ng](https://github.com/fireeye/flare-fakenet-ng)
repository contains `README.md` which documents usage and configuration; and
`docs/internals.md` which describes Diverter internals for Linux.

This specification describes the functions to be performed by FakeNet-NG when
implemented on a given platform (e.g. Windows, Linux, macOS).

## Goals
The primary goal of this specification is to help developers evaluate whether
they have implemented all that is necessary and not broken anything else while
doing so. FakeNet-NG is supported on Linux and Windows. Prior to this document,
the requirements were "specified" in a combination of the readme, the
configuration file, and the code. A unified, documented concept of what it
means to implement FakeNet-NG will aid development and evaluation of any
significant revisions to existing FakeNet-NG implementations. Finally, this
specification will aid in alternative solutions analysis in cases where
multiple possible solutions exist.

The secondary goal of this specification is to record proposed future
requirements that promote better usability or easier development. These will be
called out with the word "proposed".

The tertiary goal of this specification is to document (but not to resolve)
potential specification conflicts where the current implementation may be at
odds with the intent. These are called out with the word "TODO" and marked in
bold.

## Scope
Given the goals of this specification, requirements that will seldom or never
need to be tested may be omitted from this specification for the time being.
One example would be the "requirement" for a `--help` command line option.

[//]: # (---------------------------------------------------------------------)
[//]: # (Section break                                                        )
[//]: # (---------------------------------------------------------------------)

# Overall Description

## Design Goals

FakeNet-NG is intended to meet the following goals:

* Works Out-Of-The-Box: configured with sensible defaults for immediate use
* No installation: on applicable platforms (currently Windows), FakeNet-NG is
  released as an executable and a set of ancillary files requiring no
  installation.
* Extensible: allowing FakeNet-NG operators and Open Source Software (OSS)
  contributors to add new servers (Listeners) at will.
* Modular: servers (Listeners) should be able to run standalone without
  FakeNet-NG running (low priority, but this was one of the original
  intentions)

## Terminology

### Operators
A system administrator who configures, starts, manages, and stops FakeNet-NG
will be referred to as the Operator. This is in contrast to the term "user"
which connotes an end-user of a single interactive application.

### Network Modes
As of this writing, there are three network modes (configured in the `NetworkMode`
Diverter configuration setting) in which FakeNet-NG can be used:

| `NetworkMode` | Behavior                                                    |
|---------------|-------------------------------------------------------------|
| `SingleHost`  | Running FakeNet-NG on the same computer as the malware      |
| `MultiHost`   | Running FakeNet-NG on a different computer from the malware |
| `Auto`        | Choose the most appropriate mode given the platform         |

As of this writing, `Auto` is used to choose `SingleHost` on Windows (where
`MultiHost` is not implemented), and `MultiHost` on Linux (where the most
likely use of FakeNet-NG is to serve as a gateway and DNS server for a malware
VM).

Proposed: better names for these modes might be `Local`, `Remote`, (not
currently implemented in any FakeNet-NG release), and `Auto`.

### Configuration Settings and Sections
The configuration file used on each platform must conform to the format used by
the others. As of this writing, it is based on the Python
[ConfigParser](https://docs.python.org/2/library/configparser.html) package,
which is similar to an INI file.

### Quick Glossary of Miscellaneous Terms

| Term            | Definition |
|-----------------|------------|
| Octet           | Per [1], the networking term for an 8-bit quantity (as opposed to the term byte, which may refer to a hardware-dependent character size). |
| Packet mangling | Modification of packet data prior to datagram transmission. |
| Stray traffic   | Traffic not destined for any FakeNet-NG server component. |

Aside from numeric and text setting types, settings may also be Boolean,
requiring either `True`, `Yes`, `Enable`, `Enabled`, or `On` to enable them; and `False`,
`No`, `Disable`, `Disabled`, or `Off` to disable them.

## Components
FakeNet-NG comprises the following components:
* Application
* Configuration Logic
* Diverter
* Listeners
* Proxy Listener

For an architectural understanding of these components and their interactions,
see [FakeNet-NG Architecture](architecture.md).

Detailed component descriptions follow.

### Application
The Application is a Python entry point script (`fakenet.py` as of this
writing) that initiates FakeNet-NG's operation on the system by doing the
following:
* Reading the configuration
* Starting the appropriate Diverter for the platform
* Starting all configured listeners

### Configuration Logic
The Configuration Logic for parsing and validating the configuration file is
spread throughout the Application, Diverter, and Listeners.

The configuration file is a
[ConfigParser](https://docs.python.org/2/library/configparser.html)-compatible
file at an operator-specified location detailing how FakeNet-NG is to behave.

Proposed: it may be beneficial to better encapsulate and centralize the
configuration logic.

### Diverter
The Diverter is an object that can manipulate the local network stack to force
software to interact with FakeNet-NG's Listeners. Packets may need to be
accepted when they normally would not be; routed locally instead of to a
foreign destination; modified to reflect differing ports; et cetera. The
Diverter must perform all this manipulation as specified in the Configuration.

### Listeners
A Listener is merely a server that is configured to accept traffic on a certain
port and to adhere to certain configurable behaviors.

### Proxy Listener
The Proxy Listener is a special Listener that can be the recipient of any/all
traffic and will poll configured Listeners to determine whether they are
capable of handling the traffic.

[//]: # (---------------------------------------------------------------------)
[//]: # (Section break                                                        )
[//]: # (---------------------------------------------------------------------)

# Functional Specification

## Project-Wide Functional Specifications
The following setting(s) are not restricted to any one component or must be
conformed to by all components of FakeNet-NG.

### OS-Specific Defaults Must Work Out-Of-Box
Where a configuration setting's default value would necessarily vary on
different OSes, there must be per-OS variations of each such setting to ensure
that the default configuration works out-of-the-box on each OS.

Proposed: this might be more manageable for developers and operators if
settings of the same name were partitioned among different configuration
sections named after the relevant platform and OS version. Example:

```
[Windows]
OSSpecificSetting: WindowsyDefaultValue

[Linux]
OSSpecificSetting: LinuxyDefaultValue
```

### The System must Implement Microsoft's NCSI

The system must implement Microsoft's NCSI. This is currently codified in the
DNS and HTTP listeners.

### Reverting Local Network Configuration Upon Graceful Termination
When FakeNet-NG or a component of FakeNet-NG terminates gracefully, it must
revert any network configuration changes that it made to their original values,
except where the operator has specified otherwise.

[//]: # (---------------------------------------------------------------------)
[//]: # (Section break                                                        )
[//]: # (---------------------------------------------------------------------)

## Application Functional Specifications

### Control-C Terminates Gracefully
When the user issues the Control-C keyboard combination to the FakeNet-NG
Application (or on POSIX platforms, sends it the `SIGINT` signal), the
Application must:
* Shut down Listener instances
* Terminate packet filtering and modification
* Revert local network configuration as dictated by the project-wide functional
  specification.

### IPC Halt Control
For automation purposes, the application must accept a halt command
non-interactively through some means of IPC. This is currently implemented on
Windows and Linux by polling of a file location specified in the parameters to
the application when it is started.

### Diverter Enable/Disable
There must exist a Boolean setting to control whether the Application will
start any Diverter. In practice, this is the `DivertTraffic` setting under the
`[FakeNet]` configuration section.

When this setting is enabled, FakeNet-NG must start the Diverter associated
with the current platform.

When this setting is disabled, FakeNet-NG must not start any Diverter, must not
redirect any network traffic, and must not make any network changes other than
those expressly requested in other settings (such as DNS settings), but must
still start all specified Listeners per the configuration file.

Proposed: this setting may be more intuitive if it were migrated to the
`[Diverter]` section and named simply `Enable` (regardless of which component,
e.g. the Application, might be required to parse and validate that section in
order for this to work as expected).

[//]: # (---------------------------------------------------------------------)
[//]: # (Section break                                                        )
[//]: # (---------------------------------------------------------------------)

## Configuration Logic Functional Specifications
No configuration logic requirements will be specified until they are found to
promote the Goals of this specification.

[//]: # (---------------------------------------------------------------------)
[//]: # (Section break                                                        )
[//]: # (---------------------------------------------------------------------)

## Diverter Functional Specifications
### Diverter NetworkMode Configuration
The Diverter must implement at least `SingleHost` or `MultiHost` mode for the
`NetworkMode` setting.

The Diverter must implement `Auto` which should either select the most
appropriate mode given the platform. This may be either the mode that is the
most feature-complete, or the mode that the operator is most likely to expect
on a given platform.

In practice, Linux is the only implementation required to implement `MultiHost`
mode, whereas Windows and macOS would likely be expected to be used only in
`SingleHost` mode.

### Packet Capture Enable/Disable
The Diverter must respect the Boolean `DumpPackets` setting by writing a pcap
file to a file with an operator-specified prefix via the relevant setting.

For uniformity with current implementations, the pcap must contain 
the initial and, if mangled, final forms of traffic.

### Packet Capture Filename Specification
When the operator specifies that FakeNet-NG must capture packets, the Diverter
must prepend the generated pcap filename with the value of the
`DumpPacketsFilePrefix` setting.

### Proposed: Packet Capture Verbosity

### Redirecting All Traffic vs Some Traffic
A Boolean `RedirectAllTraffic` setting must control the dynamic forwarding of
stray traffic.

When `RedirectAllTraffic` is unset, FakeNet-NG will not mangle port numbers for
stray traffic. This is irrespective of whether the client intends to
communicate with a remote host or localhost.

When `RedirectAllTraffic` is set, FakeNet-NG will mangle port numbers for stray
traffic, directing it to the default listener.

**TODO: does the new Proxy Listener architecture respect the
`RedirectAllTraffic` setting?**

### ICMP Traffic Logging
The Diverter must at least log any ICMP traffic that it observes to the
console, user-selected log file, etc.

### Default Listeners
When `RedirectAllTraffic` is configured, the Diverter must require
configuration values specifying a `DefaultTCPListener` and a
`DefaultUDPListener` to designate which Listeners should receive stray TCP and
UDP traffic, respectively.

### Local DNS Modification
The `ModifyLocalDNS` Diverter setting must control whether FakeNet-NG takes
over as the DNS server for the local host by modifying local DNS settings.

### DNS Resolver Cache Termination
On applicable OSes (as of this writing, Windows only), the `StopDNSService`
setting should terminate the DNS resolver cache service to ensure that
FakeNet-NG can see the real origin of DNS requests rather than a generic daemon
or `svchost.exe` instance.

Proposal: Migrate this to a `[Windows]` config section.

### Foreign-Bound Traffic Redirection
FakeNet-NG must redirect packets destined for foreign hosts to FakeNet-NG
listeners and facilitate the transit of reply datagrams back to the client.

This setting should respect the FakeNet-NG Interface Restriction setting
(currently specific to Linux and named `LinuxRestrictInterface`).

### FakeNet-NG Interface Restriction
On applicable OSes (as of this writing, Linux only), when using `NetworkMode`
settings `MultiHost` (and, if applicable, `Auto`), there must exist a setting
to restrict FakeNet-NG's purview to a single network interface. The setting is
currently specific to Linux and named `LinuxRestrictInterface`.

Proposal: Resolve this to an OS-agnostic setting or migrate it to a `[Linux]`
config section.

### Linux Flush IP Tables Control
On Linux, where residual `iptables` rules may influence the behavior of the
local network stack in unknown ways, a setting must exist to allow the operator
specify whether to delete all rules and start from a clean configuration. This
setting is currently `LinuxFlushIpTables`.

Proposal: Migrate this to a `[Linux]` config section.

### DNS Resolver Cache Flush Control
On systems where the DNS resolver cache need not be disabled to identify DNS
clients and their associated requests, it is still necessary to flush the
resolver cache to ensure that all name lookups will traverse the FakeNet-NG
stack and thus appear in logging (rather than being silently serviced by the
resolver cache). As of this writing, the `LinuxFlushDnsCommand` setting serves
this purpose on Linux.

Proposal: Migrate this to a `[Linux]` config section.

### DebugLevel (Optional)
Each Diverter may support a `DebugLevel` setting with Diverter-specific and/or
OS-specific settings and semantics.

### Redirection Blacklisting
FakeNet-NG should allow the operator to permit some traffic to reach the
Internet instead of being intercepted when `RedirectAllTraffic` is enabled.

The following settings should control this:
* `BlackListPortsTCP` - what TCP ports to ignore when contemplating redirection
* `BlackListPortsUDP` - what UDP ports to ignore when contemplating redirection
* `HostBlackList` - what IP hosts to ignore when contemplating redirection
* `ProcessBlackList` - what processes to leave alone when contemplating
  redirection
* `ProcessWhiteList` - what processes to consider contemplating redirection for

### Listener Settings Implemented By Diverter
The Diverter must implement the following Listener settings to centrally and
uniformly handle certain configuration specifications that are extraneous to
Listener development.

| Setting            | Value                                                  |
|--------------------|--------------------------------------------------------|
| `ExecuteCmd`       | Text - Parameterized command to execute upon first packet |
| `ProcessWhiteList` | Text - Comma-separated list of process image names to divert |
| `ProcessBlacklist` | Text - Comma-separated list of process image names not to divert |
| `HostWhiteList`    | Text - Comma-separated list of IP addresses to divert  |
| `HostBlackList`    | Text - Comma-separated list of IP addresses not to divert |
| `Hidden`           | Boolean - whether to force packets otherwise destined for this port to go through the Proxy Listener instead |

### Black and White List Mutual Exclusivity
Black- and Whitelists are mutually exclusive. Specifying both must be handled
as a fatal error.

[//]: # (---------------------------------------------------------------------)
[//]: # (Section break                                                        )
[//]: # (---------------------------------------------------------------------)

## Listener Functional Specifications

### Listener Configuration

#### Listener Minimum Configuration
All Listeners must respect at least the following minimum set of configuration
settings or refuse to start the Listener instance if any setting cannot be
accommodated:

| Setting          | Value                                                    |
|------------------|----------------------------------------------------------|
| `Enabled`        | Boolean                                                  |
| `Port`           | Numeric - port number between 0-65535 inclusive          |
| `Protocol`       | Text - `TCP` or `UDP`                                    |
| `Listener`       | Text - name of Listener module                           |
| `UseSSL`         | Boolean                                                  |
| `Timeout`        | Numeric - seconds after which to timeout the port        |

In the case of the `Enabled` setting, the Diverter (not the Listener) is
responsible for carrying out the Operator's specification.

#### Listener Extraneous Settings Behavior
Listeners currently disregard settings that fall outside the minimum set if
they are not applicable to that Listener. In other words, Listeners don't
currently verify that all settings passed to it are applicable and handled by
that Listener.

Proposed: FakeNet-NG might better conform to user expectations by applying the
fail-early principle and having all Listeners use a uniform means to check for
settings they do not handle and refuse to start the Listener instance if one is
found.

### Support for Proxy Listener Traffic Sample Listener Identification (Taste)
Listeners must implement a `taste()` callback to allow the Proxy Listener to
identify the correct Listener to pass traffic to based on a sample of traffic
received.

### HTTP Custom Response
The HTTP Listener must accommodate Custom Response configuration constrained to
operator-configured URIs and/or hosts and permit responses to be returned
according to three configuration specifications:
* The raw contents of a configured file
* The contents of a statically configured string with selected server headers
  generated by FakeNet-NG
* The delegation of control to a Python script file

The HTTP Custom Response feature must not return server headers on behalf of
the operator except in the case where only a static string was specified for
the body of the response.

When configured to return the contents of a file or the contents of a static
string, the HTTP Custom Response feature must replace occurrences of
`<RAW-DATE>` in the 

### TCP and UDP Listener Custom Response Configuration
The TCP and UDP listeners must accommodate Custom Response configuration
and permit responses to be returned according to three configuration
specifications:
* The raw contents of a configured binary file
* The contents of a statically configured string
* The delegation of control to a Python script file

# References

1. Comer, Douglas E., Internetworking with TCP/IP, 4th Ed., Prentice Hall, 2000
