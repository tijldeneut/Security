#!/usr/bin/env python3

import threading, re, struct, time, sys
from socket import *
try:
    import ipaddress
except ImportError:
    print('\n[+] ipaddress module required!')
    print('   Please run \'pip install ipaddress\'')
    sys.exit(1)

banner = r'''
                 _____ _______        _______ _____ _______
 .--------.-----| _   |   _   |______|   _   | _   |   _   |
 |        |__ --|.|   |___|   |______|.  |   |.|   |.  |   |
 |__|__|__|_____`-|.  |  /   /       |.  |   `-|.  |.  |   |
                  |:  | |   |        |:  1   | |:  |:  1   |
                  |::.| |   |        |::.. . | |::.|::.. . |
                  `---' `---'        `-------' `---`-------'
 .--------.---.-.-----.-----.   .-----.----.---.-.-----.-----.-----.----.
 |        |  _  |__ --|__ --|   |__ --|  __|  _  |     |     |  -__|   _|
 |__|__|__|___._|_____|_____|   |_____|____|___._|__|__|__|__|_____|__|

                                        MS17-010-m4ss-sc4nn3r v1.1
                         Written by:
                       Claudio Viviani
                
                    http://www.homelab.it

                       info@homelab.it
                   homelabit@protonmail.ch

                 https://twitter.com/homelabit
               Updated for Python3 by: Photubias
'''

usage = '[+] Usage: {} ip or ip/CIDR or ip/subnet\n'.format(sys.argv[0])
usage += '    Example: {} 192.168.0.1\n'.format(sys.argv[0])
usage += '             {} 192.168.0.0/24\n'.format(sys.argv[0])
usage += '             {} 192.168.0.0/255.255.255.0\n'.format(sys.argv[0])

# Negotiate Protocol Request
packetnego = '00000054' # Session Message
packetnego += 'ff534d42'# Server Component: SMB
packetnego += '72' # SMB Command: Negotiate Protocol (0x72)
packetnego += '00' # Error Class: Success (0x00)
packetnego += '00' # Reserved
packetnego += '0000'# Error Code: No Error
packetnego += '18' # Flags
packetnego += '0128' # Flags 2
packetnego += '0000' # Process ID High 0
packetnego += '0000000000000000' # Signature
packetnego += '0000' # Reserved
packetnego += '0000' # Tree id 0
packetnego += '446d' # Process ID 27972
packetnego += '0000' # User ID 0
packetnego += '42c1' # Multiplex ID 49474
packetnego += '00' # WCT 0
packetnego += '3100' # BCC 49
packetnego += '024c414e4d414e312e3000' # LANMAN1.0
packetnego += '024c4d312e325830303200' # LM1.2X002
packetnego += '024e54204c414e4d414e20312e3000' # NT LANMAN 1.0
packetnego += '024e54204c4d20302e313200' # NT LM 0.12
packetnego = bytes.fromhex(packetnego)

def checkNet(net):
    if '/255.' in net or re.match('/[0-9][0-9]', net[-3:]) is not None or re.match('/[0-9]', net[-2:]): return True
    else: return False

def handle(data, iptarget):
    ## SMB Command: Session Setup AndX Request, User: .\
    if data[8:10] == b'\x72\x00':
        packetsession = 'ff534d42'# Server Component: SMB
        packetsession += '73' # SMB Command: Session Setup AndX (0x73)
        packetsession += '00' # Error Class: Success (0x00)
        packetsession += '00' # Reserved
        packetsession += '0000'# Error Code: No Error
        packetsession += '18' # Flags
        packetsession += '0128' # Flags 2
        packetsession += '0000' # Process ID High 0
        packetsession += '0000000000000000' # Signature
        packetsession += '0000' # Reserved
        packetsession += data[28:34].hex() # TID+PID+UID
        packetsession += '42c1' # Multiplex ID 49474
        packetsession += '0d' # WCT 0
        packetsession += 'ff' # AndXCommand: No further commands (0xff)
        packetsession += '00' # Reserved 00
        packetsession += '0000' # AndXOffset: 0
        packetsession += 'dfff' # Max Buffer: 65503
        packetsession += '0200' # Max Mpx Count: 2
        packetsession += '0100' # VC Number: 1
        packetsession += '00000000' # Session Key: 0x00000000
        packetsession += '0000' # ANSI Password Length: 0
        packetsession += '0000' # Unicode Password Length: 0
        packetsession += '00000000' # Reserved: 00000000
        packetsession += '40000000' # Capabilities: 0x00000040, NT Status Codes
        packetsession += '2600' # Byte Count (BCC): 38
        packetsession += '00' # Account:
        packetsession += '2e00' # Primary Domain: .
        packetsession += '57696e646f77732032303030203231393500' # Native OS: Windows 2000 2195
        packetsession += '57696e646f7773203230303020352e3000' # Native LAN Manager: Windows 2000 5.0
        packetsession = bytes.fromhex(packetsession)
        
        return struct.pack(">i", len(packetsession))+packetsession

    ## Tree Connect AndX Request, Path: \\ip\IPC$
    if data[8:10] == b'\x73\x00':
        share = 'ff534d42'# Server Component: SMB
        share += '75' # SMB Command: Tree Connect AndX (0x75)
        share += '00' # Error Class: Success (0x00)
        share += '00' # Reserved
        share += '0000'# Error Code: No Error
        share += '18' # Flags
        share += '0128' # Flags 2
        share += '0000' # Process ID High 0
        share += '0000000000000000' # Signature
        share += '0000' # Reserved
        share += data[28:34].hex() # TID+PID+UID
        share += '42c1' # Multiplex ID 49474
        share += '04' # WCT 4
        share += 'ff' # AndXCommand: No further commands (0xff)
        share += '00' # Reserved: 00
        share += '0000' # AndXOffset: 0
        share += '0000' # Flags: 0x0000
        share += '0100' # Password Length: 1
        share += '1900' # Byte Count (BCC): 25
        share += '00' # Password: 00
        share += '5c5c' + iptarget.encode().hex() + '5c4950432400' # Path: \\192.168.0.1\IPC$
        share += '3f3f3f3f3f00'
        share = bytes.fromhex(share)

        return struct.pack(">i", len(share))+share

    ## PeekNamedPipe Request, FID: 0x0000
    if data[8:10] == b'\x75\x00':
        smbpipefid0 = 'ff534d42'# Server Component: SMB
        smbpipefid0 += '25' # SMB Command: Trans (0x25)
        smbpipefid0 += '00' # Error Class: Success (0x00)
        smbpipefid0 += '00' # Reserved
        smbpipefid0 += '0000'# Error Code: No Error
        smbpipefid0 += '18' # Flags
        smbpipefid0 += '0128' # Flags 2
        smbpipefid0 += '0000' # Process ID High 0
        smbpipefid0 += '0000000000000000' # Signature
        smbpipefid0 += '0000' # Reserved
        smbpipefid0 += data[28:34].hex() # TID+PID+UID
        smbpipefid0 += '42c1' # Multiplex ID 49474
        smbpipefid0 += '10' # Word Count (WCT): 16
        smbpipefid0 += '0000' # Total Parameter Count: 0
        smbpipefid0 += '0000' # Total Data Count: 0
        smbpipefid0 += 'ffff' # Max Parameter Count: 65535
        smbpipefid0 += 'ffff' # Max Data Count: 65535
        smbpipefid0 += '00' # Max Setup Count: 0
        smbpipefid0 += '00' # Reserved: 00
        smbpipefid0 += '0000' # Flags: 0x0000
        smbpipefid0 += '00000000' # Timeout: Return immediately (0)
        smbpipefid0 += '0000' # Reserved: 0000
        smbpipefid0 += '0000' # Parameter Count: 0
        smbpipefid0 += '4a00' # Parameter Offset: 74
        smbpipefid0 += '0000' # Data Count: 0
        smbpipefid0 += '4a00' # Data Offset: 74
        smbpipefid0 += '02' # Setup Count: 2
        smbpipefid0 += '00' # Reserved: 00
        smbpipefid0 += '2300' # Function: PeekNamedPipe (0x0023)
        smbpipefid0 += '0000' # FID: 0x0000
        smbpipefid0 += '0700' # Byte Count (BCC): 7
        smbpipefid0 += '5c504950455c00' # Transaction Name: \PIPE\
        smbpipefid0 = bytes.fromhex(smbpipefid0)

        return struct.pack(">i", len(smbpipefid0))+smbpipefid0

def conn(sTarget):
    boolVuln = False
    try:
        oSock = socket(AF_INET, SOCK_STREAM)
        oSock.settimeout(10)
        oSock.connect((str(sTarget), 445))
        oSock.send(packetnego)

        try:
            while True:
                data = oSock.recv(1024)

                # Get Native OS from Session Setup AndX Response
                if data[8:10] == b'\x73\x00': nativeos = data[45:100].split(b'\x00' * 1)[0]
                
                ## Trans Response, Error: STATUS_INSUFF_SERVER_RESOURCES
                if data[8:10] == b'\x25\x05':
                    ## 0x05 0x02 0x00 0xc0 = STATUS_INSUFF_SERVER_RESOURCES
                    if data[9:13] == b'\x05\x02\x00\xc0':
                        print('[+] {} is likely VULNERABLE to CVE-2017-0143 ({})'.format(sTarget, nativeos.decode()))
                        boolVuln = True
                        oSock.close()
                        break
                
                oSock.send(handle(data, sTarget))

        except Exception as msg:
            oSock.close()
            pass

    except Exception as msg:
        if not boolMultiScanCheck:
            print('[+] Can\'t connect to {}'.format(sTarget))
            sys.exit(1)
        pass

    return boolVuln

if len(sys.argv)<=1 or '-h' in sys.argv:
    print(banner)
    print(usage)
    sys.exit(1)

print(banner)

ip = sys.argv[1]

boolMultiScanCheck = checkNet(ip)

threads = []

if boolMultiScanCheck:
    net4 = ipaddress.ip_network(ip, strict=False)
    totip = 0
    start_time = time.time()
    for i in net4.hosts():
        if str(i)[-2:] != '.0' and str(i)[-4:] != '.255':
            totip += 1
            t = threading.Thread(target=conn, args=(i,))
            threads.append(t)
            t.start()
            time.sleep(0.01)

    for a in threads: a.join()

    print('\n[+] ' + str(totip) + ' IP addresses checked in %s seconds ' % (time.time() - start_time))
else:
    if not conn(ip):
        print('[+] {} NOT vulnerable to MS17-010'.format(ip))
