# GeneralSecurityScripts
--> Please note, unless mentioned otherwise, all scripts work on both Linux and Windows, and for Python2 or 3 (look at the first line)
* GetNessusHomeCode.py: Automated registration for new Nessus Home Feed license
* DownloadNessus.py: Automated script for downloading the most recent Nessus version (Linux version only)
* Live_Browser_Password_Dumper.py: Python3 script to dump/export credentials from Chrome, Edge (new) and Opera, (pip3 install pycryptodome pypiwin32)
* rdpstrip.py: Automated MitM script for non-NLA Remote Desktop sessions
* snmpAutoenum.py: Automated, multi-threaded SNMP scanner, including parsing with configurable rules
* SubnetScanner.py: This script tries to find reachable subnets on a given network
* DumpSomeHashes: Two scripts to demonstrate how Windows retrieves hashes from the registry, also works on Windows 10 >v1607 (AES Encryption)
* IPMI-Scan-Hashes.py: Multi-threaded and automated scanner for finding IPMI systems on a subnet and dumping hashes unauthenticated
* CVE-2020-0688.py: Native scanner and exploit (no extra's required) for MS Exchange Server Authenticated RCE/LPE (as System)
* CVE-2020-11108.py: Native exploit script for Pi-hole 4.4.0 (Pi-hole v4.4.0-g9e49077, Web v4.3.3,v4.3.2-1-g4f824be, FTL v5.0) for web authenticated RCE + LPE
* CVE-2020-12720.py: Native exploit script for vBulletin v5.6.1 (might also work on older versions of v5) for Admin Account takeover using SQLi plus authenticated RCE
* CVE-2020-3952.py: Native exploit script for vCenter Server 6.7 random user adding and escalation (Authentication Bypass), mirror: 
https://www.exploit-db.com/exploits/48535
* CVE-2021-2109.py: Exploit script for WebLogic 14.1.1.0 and JDK's under 6u201, 7u191, 8u182 & 11.0.1 (Authenticated RCE), mirror: https://www.exploit-db.com/exploits/49461
* Exchange-fingerprinter.py: Grab the version number from any reachable Exchange server and verify two vulnerabilities
* VMware-fingerprinter.py: Automated, multi-threaded VMware enumeration scanner, including a couple more critical vulnerability detections
* CVE-2021-21972.py: Exploit & checker for VMware vCenter Unauthenticated Upload & RCE, should work in one way or another against vCenter Server 6.5 up to 7.0
* ArpEnum.py: Quickly find hosts on a local network via ARP
* FortiGate-Live-IOC-Checker.py: Given correct credentials, this script verifies files and dates for known IOC's for COATHANGER and CVE-2022-42475
