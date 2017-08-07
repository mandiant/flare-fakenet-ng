#!/bin/sh

sudo iptables -t nat -F

sudo iptables -t nat -I PREROUTING --src 0/0 --dst 0/0 -p udp ! --dport 8888 -j REDIRECT --to-ports 8888
sudo iptables -t nat -I PREROUTING --src 0/0 --dst 0/0 -p tcp ! --dport 9999 -j REDIRECT --to-ports 9999

#sudo iptables -t nat -A PREROUTING -i ens32 -p tcp -j REDIRECT --to-port 9999
#sudo iptables -t nat -A PREROUTING -i ens32 -p udp -j REDIRECT --to-port 8888

sudo iptables -t nat -L -n -v
