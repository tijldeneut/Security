# GeneralSecurityScripts
--> Please note, unless mentioned otherwise, all scripts work on both Linux and Windows
* ArpEnum.py: Quickly find hosts on a local network via ARP
* CVE-2018-1207.py: iDRAC: RCE for Integrated Dell Remote Access Console
* CVE-2019-6693.py: FortiGate: Native authenticated information retrieval (clear text passwords) for unaltered FortiGate devices (0-day)
* CVE-2020-0688.py: MS Exchange Server: Native scanner and exploit (no extra's required) for Authenticated RCE/LPE (as System), mirror: https://www.exploit-db.com/exploits/48153
* CVE-2020-11108.py: Pi-hole: Native exploit script for Pi-hole 4.4.0 (Pi-hole v4.4.0-g9e49077, Web v4.3.3,v4.3.2-1-g4f824be, FTL v5.0) for web authenticated RCE + LPE, mirror: https://www.exploit-db.com/exploits/48519
* CVE-2020-12720.py: Native exploit script for vBulletin v5.6.1 (might also work on older versions of v5) for Admin Account takeover using SQLi plus authenticated RCE, mirror: https://www.exploit-db.com/exploits/48472
* CVE-2020-3952.py: Native exploit script for vCenter Server 6.7 random user adding and escalation (Authentication Bypass), mirror: https://www.exploit-db.com/exploits/48535
* CVE-2021-2109.py: Exploit script for WebLogic 14.1.1.0 and JDK's under 6u201, 7u191, 8u182 & 11.0.1 (Authenticated RCE), mirror: https://www.exploit-db.com/exploits/49461
* CVE-2021-21972.py: Exploit & checker for VMware vCenter Unauthenticated Upload & RCE, should work in one way or another against vCenter Server 6.5 up to 7.0 (newer versions untested), mirror: https://www.exploit-db.com/exploits/49602
* CVE-2021-35464.py: ForgeRock Access Manager, Unauthenticated RCE, mirror: https://www.exploit-db.com/exploits/50131
* CVE-2023-3519-Checker.py: Verify a list of Citrix Netscaler URL's for vulnerability checks
* CVE-2023-48795-Checker.py: SSH Terrapin Checker, verifies presence of specific protocols
* CVE-2024-38063-Checker.py: Windows IPv6 vulnerability checker, not 100% reliable yet
* CVE-2024-38063-DOS.py: Windows IPv6 vulnerability exploiter, Denial-Of-Service, mirror: https://www.exploit-db.com/exploits/52075
* EntraIDMFAPoker.py: Verifies for given username/password of MFA is réally enabled on several known EntraID resources
* FortiGate-Live-IOC-Checker.py: Given correct credentials, this script verifies files and dates for known IOC's for COATHANGER and CVE-2022-42475
* IPMI-Scan-Hashes.py: Multi-threaded and automated scanner for finding IPMI systems on a subnet and dumping hashes unauthenticated
* Live_Browser_Password_Dumper.py: Python3 script to dump/export credentials from Chrome, Edge (new) and Opera, (pip3 install pycryptodome pypiwin32)
* DownloadNessus.py: Automated script for downloading the most recent Nessus version (Linux version only)
* NessusGetHomeCode.py: Automated registration for Nessus Home Feed license
* SubnetScanner.py: This script tries to find reachable subnets on a given network
* ms17-010-m4ss-sc4nn3r.py: Python3 version of official MS17-010 scanner by Claudio Vivian
* rdpstrip.py: Automated MitM script for non-NLA Remote Desktop sessions (python2-only)
* smb-vuln-cve-2020-0796.nse: NSE script updated for Nmap 7.92, officially by psc4re

Folders: 
* DumpSomeHashes: Two scripts to demonstrate how Windows retrieves hashes from the registry, also works on Windows 10 >v1607 (AES Encryption)
* VMware: Automated, multi-threaded VMware enumeration scanner, including OPSEC safe, critical vulnerability detections, and some decryption scripts
* kaliScripts: some easy-to-use scripts for Kali
* Fingerprinters:
  * cups-fingerprinter.py: Multithreaded and native scanner to get versions of CUPS (UDP/631) (Has Server & Scanning component, can be run separately)
  * rsync-fingerprinter.py: Multithreaded and native scanner to get versions of RSYNC (TCP/873), includes vulnerability scanning and listing modules (shares)
  * SSH-fingerprinter.py: Multi-threaded scanner for SSH services, shows banners and scans for critical vulnerabilities
  * snmpAutoenum.py: Automated, multi-threaded SNMP scanner, including parsing with configurable rules
  * Exchange-fingerprinter.py: Grab the version number from any reachable Exchange server and OPSEC safe, critical vulnerability detections
  * iDRAC-fingerprinter.py: Version enumerator for iDRAC systems (currently iDRAC8 & iDRAC9) including OPSEC safe, critical vulnerability detections
