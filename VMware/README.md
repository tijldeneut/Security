# VMware Scripts
--> Please note, unless mentioned otherwise, all scripts work on both Linux and Windows, and for Python 3
* VMware-fingerprinter.py: Automated, multi-threaded VMware enumeration scanner, including a couple more critical vulnerability detections
* VMware-vCenter-decryptor.py: Scans and decodes ESXi Hosts' vpxuser passwords from vCenter installations
* VMware-vCenter_saml_login.py: Generate a SSO browser cookie for vCenter when provided with the MDB file
  - Prerequisite: python3 -m pip install requests bitstring signxml python-dateutil
