# Testing

Procedure:
* Windows
	* General - Port and IP Redirection
	* General - Listeners
	* SingleHost Mode
* Linux SingleHost
	* General - Port and IP Redirection
	* General - Listeners
	* SingleHost Mode
* Linux MultiHost
	* General - Port and IP Redirection
	* General - Listeners
	* MultiHost Mode

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
	* ping <fakenet> e.g. `ping 192.168.x.x`
	* ping <arbitrary> e.g. `ping 1.1.1.1`
	* ping <DNS> e.g. `ping 1.1.1.1`
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
	* NetworkMode: MultiHost (Linux only)
	* LinuxRedirectNonlocal (Linux only) - redirects foreign-bound packets to localhost

## SingleHost Mode

Applies to:
* Windows SingleHost
* Linux SingleHost

0. Diverter Settings
	* NetworkMode: SingleHost (Linux only)
	* DumpPackets - causes pcaps to be written
	* DumpPacketsFilePrefix - changes pcap name prefix
    * FixGateway seting
    * FixDNS (Windows only) sets to x.x.x.254 IF it was not already set
    * ModifyLocalDNS unconditionally sets to local IP (not 127.x.x.x)
	* LinuxFlushDNSCommand (Linux only)
	* StopDNSService (Windows only)
	* RedirectAllTraffic - disabling stops port redirection
	* DefaultTCPListener - TODO: Devise test
	* DefaultUDPListener - TODO: Devise test
	* BlacklistPortsUDP
	* BlacklistPortsTCP
    * ProcessBlackList (global)
    * ProcessWhiteList (global)
	* HostBlackList (global)

0. Listener Settings
	* ProcessBlackList (per-listener)
	* ProcessWhiteList (per-listener)
	* HostWhiteList (per-listener)
	* HostBlackList (per-listener)
	* ExecuteCmd - e.g. `echo "Process {procname} ({pid}) {src_addr}:{src_port}->{dst_addr}:{dst_port}" 1> ~whoever/flag.txt`
