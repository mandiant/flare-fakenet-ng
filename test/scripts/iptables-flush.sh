#!/bin/bash

iptables --flush -t nat
iptables --flush -t mangle
iptables --flush -t raw
iptables --flush -t filter
