#!/bin/bash
apt-get update
apt-get upgrade -y
apt-get autoremove -y
msfupdate
service nessusd stop
/opt/nessus/sbin/nessuscli update --all
openvas-feed-update
wpscan --update
#nikto -update ## replace with cd ?? && git pull
nmap --script-updatedb