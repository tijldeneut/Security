# GeneralSecurityScripts
--> Please note, unless mentioned otherwise, all scripts work on both Linux and Windows, and for Python2 or 3 (look at the first line)
* GetNessusHomeCode.py: Automated registration for new Nessus Home Feed license
* DownloadNessus.py: Automated script for downloading the most recent Nessus version (Linux version only)
* rdpstrip.py: Automated MitM script for non-NLA Remote Desktop sessions
* snmpAutoenum.py: Automated, multi-threaded SNMP scanner, including parsing with configurable rules
* SubnetScanner.py: This script tries to find reachable subnets on a given network
* DumpSomeHashes: Two scripts to demonstrate how Windows retrieves hashes from the registry, also works on Windows 10 >v1607 (AES Encryption)
* IPMI-Scan-Hashes.py: Multi-threaded and automated scanner for finding IPMI systems on a subnet and dumping hashes unauthenticated
* CVE-2020-0688.py: Native scanner and exploit (no extra's required) for MS Exchange Server Authenticated RCE/LPE (as System)
* CVE-2020-11108.py: Native exploit script for Pi-hole 4.4.0 (Pi-hole v4.4.0-g9e49077, Web v4.3.3,v4.3.2-1-g4f824be, FTL v5.0) for web authenticated RCE + LPE
* CVE-2020-12720.py: Native exploit script for vBulletin v5.6.1 (might also work on older versions of v5) for Admin Account takeover using SQLi plus authenticated RCE
* CVE-2020-3592.py: Native exploit script for vCenter Server 6.7 random user adding and escalation (Authentication Bypass), mirror: 
https://www.exploit-db.com/exploits/48535
