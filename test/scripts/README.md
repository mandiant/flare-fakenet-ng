# Testing / Diagnostic Scripts

## iptables scripts
For viewing/flushing all iptables rules. One useful command is `sudo watch -n 1
./iptables-list.sh` (ideally within `screen` or `tmux` which allows for a
near-real-time view of rules as they are added.

## ncscript.sh
Sometimes uniform and uncreative testing tools lend to turning a blind eye to
cases that need attention. On the other hand, sometimes not having anything for
testing can lend to developing code without properly testing it or discourage
development due to the burden of testing. On the premise that the latter is
worse than the former, `ncscript.sh` is a quick test of the ordinary NAT and
dynamic port forwarding cases FakeNet-NG is meant to handle.
