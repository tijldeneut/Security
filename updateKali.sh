#!/bin/bash
apt-get update
apt-get upgrade -y
apt-get autoremove -y
msfupdate
service nessusd stop
/opt/nessus/sbin/nessuscli update --all
openvas-feed-update
wpscan --update
#nikto -update ## no longer part of Kali?
nmap --script-updatedb
