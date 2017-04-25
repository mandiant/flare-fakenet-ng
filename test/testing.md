# Testing

## General

Applies to:
* Windows
* Linux MultiHost
* Linux SingleHost

### Port and IP Redirection

0. TCP
	* Test <fakenet> @ bound port e.g. `echo hi | nc -v 192.168.x.x 1337`
	* Test <fakenet> @ unbound port e.g. `echo hi | nc -v 192.168.x.x 1338`
	* Test <arbitrary> @ bound port e.g. `echo hi | nc -v 8.8.8.8 1337`
	* Test <arbitrary> @ unbound port e.g. `echo hi | nc -v 8.8.8.8 1338`
	* Test <dnsname> @ bound port e.g. `echo hi | nc -v www.fireeye.com 1337`
	* Test <dnsname> @ unbound port e.g. `echo hi | nc -v www.fireeye.com 1338`
0. UDP
	* Test FakeNet host / bound port e.g. `echo hi | nc -u -v 192.168.x.x 1337`
	* Test FakeNet host / unbound port e.g. `echo hi | nc -u -v 192.168.x.x 1338`
	* Test arbitrary host / bound port e.g. `echo hi | nc -u -v 8.8.8.8 1337`
	* Test arbitrary host / unbound port e.g. `echo hi | nc -u -v 8.8.8.8 1338`
	* Test DNS host / bound port e.g. `echo hi | nc -u -v www.fireeye.com 1337`
	* Test DNS host / unbound port e.g. `echo hi | nc -u -v www.fireeye.com 1338`
0. ICMP
	* ping <fakenet> e.g. ping 192.168.x.x
	* ping <arbitrary> e.g. ping 1.1.1.1
	* ping <DNS> e.g. ping 1.1.1.1
	* (Verify these are logged as well)

### Listeners

0. DNS - nslookup <anyname> e.g. `nslookup fireeye.com`
0. HTTP - wget localhost 
0. FTP
	* user
	* pass
	* ls
	* get FakeNet.gif
0. TFTP
0. IRC
0. POP
0. Raw
0. SMTP

## MultiHost Mode (Linux only)

Applies to:
* Linux MultiHost

0. Diverter Settings
	0. NetworkMode: MultiHost (Linux only)
	0. LinuxRedirectNonlocal (Linux only) - redirects foreign-bound packets to localhost

## SingleHost Mode

Applies to:
* Windows SingleHost
* Linux SingleHost

0. Diverter Settings
	0. NetworkMode: SingleHost (Linux only)
	0. DumpPackets - causes pcaps to be written
	0. DumpPacketsFilePrefix - changes pcap name prefix
    0. FixGateway seting
    0. FixDNS (Windows only) sets to x.x.x.254 IF it was not already set
    0. ModifyLocalDNS unconditionally sets to local IP (not 127.x.x.x)
	0. LinuxFlushDNSCommand (Linux only)
	0. StopDNSService (Windows only)
	0. RedirectAllTraffic - disabling stops port redirection
	0. DefaultTCPListener - TODO: Devise test
	0. DefaultUDPListener - TODO: Devise test
	0. BlacklistPortsUDP
	0. BlacklistPortsTCP
    0. ProcessBlackList (global)
    0. ProcessWhiteList (global)
	0. HostBlackList (global)

0. Listener Settings
	0. ProcessBlackList (per-listener)
	0. ProcessWhiteList (per-listener)
	0. HostWhiteList (per-listener)
	0. HostBlackList (per-listener)
	0. ExecuteCmd
