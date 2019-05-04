# FakeNet-NG Test Plan
This test plan informs developers how to quality assure FakeNet-NG by using two
test suites:
* Automated Test Suite
* Manual Test Suite

If you just want to know how to test FakeNet-NG, see the following sections:
* Dev and Test Setup
* Using `test.py`
* Automated Test Suite
* Manual Test Suite

For brief highlights of why things are the way they are, read straight through.

## Testing Needs
FakeNet-NG has numerous features and specifications that are sometimes mutually
exclusive. Adding and testing new FakeNet features while a configuration
setting is in one disposition can lead to unanticipated failure when that
setting is changed.

FakeNet manipulates the network, so most network-based test control
mechanisms may be difficult to configure/coordinate with FakeNet's features,
and unreliable in cases where FakeNet fails (or even potentially in cases
where it behaves as designed).

Consequently, the bulk of testing is currently automated by interactively
executing the test script `test/test.py`. Several features are too complicated
to incorporate into a script and must be tested manually.

## Dev and Test Setup
It is recommended to use at least a Linux VM and a Windows VM for development
and testing.

The Linux guest should have at least two network interfaces. This is necessary
for testing that the `LinuxRestrictInterface` feature has not been broken by
recent changes. It also may be convenient to leave one interface connected to
NAT to reduce time spent switching networks between pushing changes versus
testing.

Meanwhile, the Windows guest should have git installed even if that is not
where development takes place, for convenience in pulling down updated branches
for testing. Note that on Windows, FakeNet has to be installed via `setup.py`
for the test script (`test.py`) to use the latest changes.

It is easiest to avoid false test results and troubleshooting issues if both
guests are tested on a host-only network as opposed to having access to the
public Internet.

### Using the Windows Guest to Test Linux MultiHost Operation
To use the Windows test machine to test Linux `MultiHost` mode, the Windows
machine must use the FakeNet-NG host as its gateway and DNS server.

On Windows:
* Run the Network Connections control panel (`ncpa.cpl`)
* Right-click on the network adapter and click `Properties`
* Select `Internet Protocol Version 4 (TCP/IPv4)`
* Click the `Advanced...` button
* In the IP Settings tab under Default gateways, click `Add...` (or `Edit...`
  if a gateway is already defined)
    * In the `TCP/IP Gateway Address` dialog, enter the IP address of the
      FakeNet machine
    * Leave `Automatic metric` alone
    * Click the `Add` button
* In the DNS tab, click `Add...`
    * In the `TCP/IP DNS Server` dialog, enter the IP address of the FakeNet
      machine again
    * Click Add
* Save all the settings by clicking `OK`
* Ping the FakeNet IP to ensure connectivity
* Commence testing

Note that you will need to copy automatically generated configuration files to
the FakeNet machine during testing. For details, see the section titled "Using
`test.py`".

## Using test.py

### Test Script Dependencies
The test script requires dependencies over and above what FakeNet calls for. As
of this writing, they include:
* `pyping`
* `irc`
* `requests`

### Test Script Usage
FakeNet supports Internet simulation for the local machine (i.e. in
`SingleHost` mode) and by acting as the gateway and DNS server for a remote
machine (i.e. `MultiHost` mode). For a handful of tests, the test script needs
to know the IP address where FakeNet is running and in what `NetworkMode`.
Consequently, the test script requires you to specify a `<where>` parameter.
You can specify either the literal word `here` to test locally, or a
dot-decimal IP address to test remotely:

```
Usage: test.py <where> [matchspec1 [matchspec2 [...] ] ]

Valid where:
  here
  Any dot-decimal IP address

Each match specification is a regular expression that
will be compared against test names, and any matches
will be included. Because regular expression negative
matching is complicated to use, you can just prefix
a match specification with a minus sign to indicate
that you would like to include only tests that do NOT
match the expression.
```

If you are testing remotely the test script will create a custom configuration
file for each subsuite of tests that it runs. You must copy that configuration
to the place where FakeNet is running and launch FakeNet specifying that config
file using the `-c` argument. This is done for you when testing locally.

The test script also allows positive and negative matching rules in order to
include or exclude tests.

Some of this may duplicate `pytest` functionality. If someone can refactor this
into `pytest`, that is fine, but the current script serves.

### Test Script Idiosynchrasies
The salient peculiarity of `test.py` is that on Windows it requires you to
install FakeNet and it then runs the global `fakenet.exe` script entry point
available via the Windows path environment variable; and on Linux, it executes
`python fakenet.py` directly. Alas, this is for purely undocumented and
forgettable reasons. It shouldn't be too difficult to make these consistent if
that becomes important to someone.

## Detailed Test Plan
Testing in only one configuration leads to quality issues. If you wish to merge
code to master, your code must pass tests in all the combinations described
here.


### Jargon
A test suite specifies a series of tests that must be completed.

By and large, specific features subject to testing are called out by the name
of the corresponding configuration setting name in FakeNet's configuration file
schema. Otherwise, they may be specified by the corresponding entry in the
[FakeNet-NG Software Requirements Specification (SRS)](srs.md).

If a setting name is ambiguous among multiple INI-style `[sections]`, it can be
disambiguated in dot format, e.g. `Diverter.ProcessBlacklist` to specify the
global process blacklist rather than the listener-specific setting
`<Listener>.ProcessBlacklist`.

Completely testing a setting indicates testing against every disposition the
setting may take (e.g. enabled, disabled).

Where settings may be omitted entirely or left empty, their disposition can be
called "unconfigured". The opposing disposition is referred to as "configured".

Where features are to be tested "against" or "versus" some other factor, it
means testing all setting values against all dispositions for each factor. For
example:

`RedirectAllTraffic` *versus* destination IP *versus* port disposition

Means testing the following feature and factor dispositions:
* `RedirectAllTraffic` feature:
    * Enabled
    * Disabled
* Destination IP factor (what IP is the test hitting?):
    * External IP - IP of the host running FakeNet
    * Arbitrary host - arbitrary IP
    * Named host - IP returned by FakeNet DNS Listener in response to a DNS A
      request
    * Localhost (if in SingleHost mode) - In practice, 127.0.0.1
* Port disposition factor (is there a listener here?):
    * Bound - A FakeNet listener is bound to the destination port under test
    * Unbound - No FakeNet listener is bound to the destination port under test

This would amount to 2 x 4 x 2 = 16 total tests.

Tests such as the above may be subdivided to indicate which sets of
dispositions are handled together or apart.

### Test Dimensions
FakeNet-NG supports two (2) platforms:
* Windows
* Linux

FakeNet-NG supports two operating modes via the `NetworkMode` configuration
setting:
* `SingleHost` (both platforms)
* `MultiHost` (Linux only as of this writing)

Notably, `Auto` is not a distinct `NetworkMode`; it selects `SingleHost` on
Windows and `MultiHost` on Windows.

In `MultiHost` mode, FakeNet only expressly supports clients running Windows
operating systems. Optionally testing with clients running Linux may pose an
opportunity to proactively discover more issues.

Hence, FakeNet must be tested in the following combinations of platforms,
modes, and clients:

| FakeNet platform | `NetworkMode` | Test Client | Client platform | Note     |
|------------------|---------------|-------------|-----------------|----------|
| Windows          | `SingleHost`  | (Local)     | (Windows)       |          |
| Linux            | `SingleHost`  | (Local)     | (Linux)         |          |
| Linux            | `MultiHost`   | Remote      | Windows         |          |
| Linux            | `MultiHost`   | Remote      | Linux           | Optional |

In each combination, FakeNet must be tested against the full range of
applicable tests in the Automated Test Suite provided by the test script
`test/test.py`.

As of this writing, the Manual Test Suite must also be executed if the FakeNet
feature set is to be fully exercised for quality assurance of a given release.

### Automated Test Suite
Run `test/test.py` against the FakeNet instance.

#### Automated Test Subsuites
The Automated Test Suite contains the following automated test subsuites and
tests.

The "No Redirect" subsuite tests:
* `RedirectAllTraffic = No` vs. destination IP vs. port disposition

The "Global process blacklist" subsuite tests:
* Only in `SingleHost` mode:
    * `Diverter.ProcessBlacklist` configured

The "Global process whitelist" subsuite tests:
* Only in `SingleHost` mode:
    * `Diverter.ProcessWhitelist` configured

The "General" subsuite tests:
* TCP listener vs. destination IP vs. port disposition
* UDP listener vs. destination IP vs. port disposition
* ICMP external IP
* ICMP arbitrary host
* ICMP domain name
* DNS listener
* HTTP listener
* HTTP listener `Custom` response versus URI/hostname/negative
* FTP listener
* POP3 listener
* SMTP listener
* SMTP SSL listener
* IRC listener
* Proxy listener and port unbound
* Proxy listener and port bound and listener `Hidden`
* `HostBlackList`
* `BlackListPortsTCP` - Redirection Blacklisting
* `BlackListPortsUDP` - Redirection Blacklisting
* Only in `SingleHost` mode:
    * `<Listener>.ProcessBlacklist` configured - Redirection Blacklisting
    * `<Listener>.ProcessWhitelist` configured - Redirection Blacklisting
    * `<Listener>.HostBlacklist` configured - Redirection Blacklisting
    * Incorrect test as of this writing: `<Listener>.HostWhitelist` configured
* Hidden versus unproxied (exposed) listeners via listener setting `Hidden`

### Manual Test Suite
The following significant features either need tests added to the automated
suite, or must be tested manually.

#### Manual Test Subsuites
The "Manual Forever" Subsuite includes features that likely will always have to
be tested manually:
* `LinuxRestrictInterface` - FakeNet-NG Interface Restriction in `MultiHost`
  mode

The "Manual But Shouldn't Be" Subsuite includes features that should definitely
have tests added to the automated suite when possible:
* `ExecuteCmd` configured
* Microsoft NCSI support

The "Manual Low-Priority" Subsuite includes lower-priority items should
probably also have tests added to the automated test suite when time permits:
* Running and testing each listener in standalone mode as its own Python script
* Control-C Terminates Gracefully
* IPC Halt Control
* Linux Flush IP Tables Control
* Diverter Enable/Disable
* Syslog logging
* Packet Capture Enable/Disable
* Packet Capture Filename Specification
* ICMP Traffic Logging
* `LinuxFlushIptables`
* `LinuxFlushDNSCommand` - DNS Resolver Cache Flush Control
* `FixGateway`
* `FixDNS`
* `ModifyLocalDNS` - Local DNS Modification
* `StopDNSService` (Windows only) - DNS Resolver Cache Termination
* HTTP CustomResponse `<RAW-DATE>` replacement
* Black and White List Mutual Exclusivity

### Features Inherently Tested
Several important FakeNet-NG features are exercised inherently by adhering to
the test plan. These include, but are not limited to:
* Diverter `NetworkMode` Configuration
* Foreign-Bound Traffic Redirection

### Known and Suspected Deficiencies in FakeNet and its Tests
The following tests are known to fail for some or all platform combinations:
* `SMTP SSL listener test` (any platform combination)
* `IRC listener test` (works on Linux, not on Windows)

As of this writing, the `Listener host whitelist` test under `SingleHostMode`
in the Automated test suite (General subsuite) is incorrect for testing the
behavior of the setting `<Listener>.HostWhitelist` when it is configured.

The functional status of process blacklisting on Linux is indeterminate: it was
thought to have been deficient, however it may have been observed passing the
tests in the automated test suite.
