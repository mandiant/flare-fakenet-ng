#!/bin/bash

server=192.168.19.222
otherhost=8.8.8.8
dnsname=www.anywhere.com
bound=1337
unbound=1338
NC_UDP_FLAGS=-w 2 -u

function test_case {
	echo ----------------------------- $1 $2 / $3 -----------------------------
	cmdline="nc -v $6 $7 $8 $4 $5"
	echo Running "${cmdline}"
	echo asdf | ${cmdline}
	echo
}

echo ================================================================================
echo                                      TCP
echo ================================================================================

test_case TCP local bound ${server} ${bound}
test_case TCP local unbound ${server} ${unbound}
test_case TCP nonlocal bound ${otherhost} ${bound}
test_case TCP nonlocal unbound ${otherhost} ${unbound}
test_case TCP DNS-nonlocal bound ${dnsname} ${bound}
test_case TCP DNS-nonlocal unbound ${dnsname} ${unbound}

echo ================================================================================
echo                                      UDP
echo ================================================================================

test_case UDP local bound ${server} ${bound} ${NC_UDP_FLAGS}
test_case UDP local unbound ${server} ${unbound} ${NC_UDP_FLAGS}
test_case UDP nonlocal bound ${otherhost} ${bound} ${NC_UDP_FLAGS}
test_case UDP nonlocal unbound ${otherhost} ${unbound} ${NC_UDP_FLAGS}
test_case UDP DNS-nonlocal bound ${dnsname} ${bound} ${NC_UDP_FLAGS}
test_case UDP DNS-nonlocal unbound ${dnsname} ${unbound} ${NC_UDP_FLAGS}

echo ================================================================================
echo                                     ICMP
echo ================================================================================
echo ----------------------------- ICMP local -----------------------------
ping -c 1 ${server}
echo ----------------------------- ICMP nonlocal -----------------------------
ping -c 1 ${otherhost}
echo ----------------------------- ICMP DNS nonlocal -----------------------------
ping -c 1 ${dnsname}
