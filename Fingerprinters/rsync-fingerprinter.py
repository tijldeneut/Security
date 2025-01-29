#! /usr/bin/python3
# -*- coding: utf-8 -*- 
r'''
	Copyright 2025 Photubias(c)
    
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

    This should work on Linux & Windows using Python3
        
    File name rsync-fingerprinter.py
    written by Photubias

    --- RSYNC Version Fingerprinter ---
    - Uses TCP/873 (rsyncd daemon)

    ## Vulns:
    CVE-2024-12084 : Buffer Overflow in RSYNC <= 3.3.0, fixed as of 3.4.0
'''
import socket, optparse, os
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat
iTimeout= 5
boolUnauthenticatedAccess = False
bOurBanner = b'@RSYNCD: 30.0 sha512 sha256 sha1 md5 md4\n'
lstTargetModules = []

def getVulns(sIP, iPort, sVersion): ## Version is a string like "32.0" which corresponds with 3.2.0
    ## CVE-2024-12084: Remote Code Execution via Buffer Overflow: https://nsfocusglobal.com/rsync-buffer-overflow-and-information-disclosure-vulnerability-cve-2024-12084-cve-2024-12085-notification/
    sVuln = f'  [!!] {sIP}:{iPort} is vulnerable to CVE-2024-12084: RCE via Buffer Overflow'
    try: iVersion = int(sVersion.replace('.',''))
    except: return
    if iVersion < 340: print(sVuln)
    return

def getIPs(sCIDR):
    def dec2bin(iN,d=None):
        sReturn = ''
        while iN>0:
            if iN&1: sReturn = '1' + sReturn
            else: sReturn = '0' + sReturn
            iN >>= 1
        if d is not None:
            while len(sReturn)<d: sReturn = '0' + sReturn
        if sReturn == '': sReturn = '0'
        return sReturn
    
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
        for i in range(0,len(b),8): ip += str(int(b[i:i+8],2)) + '.'
        return ip[:-1]

    iplist=[]
    parts = sCIDR.split('/')
    if len(parts) == 1:
        iplist.append(parts[0])
        return iplist
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    if subnet == 32: iplist.append(bin2ip(baseIP))
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)): iplist.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
    return iplist

def getIPsFromFile(sFile):
    lstLines = open(sFile,'r').read().splitlines()
    lstIPs = []
    for sLine in lstLines: ## Line can be an IP or a CIDR
        for sIP in getIPs(sLine): lstIPs.append(sIP)
    return lstIPs

def parseResponse(sSource, bData, boolVerbose):
    lstResponse = bData.split(b'\n')
    sName = sComment = None
    lstModules = []
    for bLine in lstResponse:
        if b'RSYNCD: EXIT' in bLine: break
        if not b'\t' in bLine: continue
        lstData = bLine.split(b'\t')
        sName = lstData[0].decode(errors='none').strip()
        sComment = lstData[1].decode(errors='none').strip()
        lstModules.append((sName, sComment))
        if boolVerbose: 
            print(f'    System {sSource} has responded:\n     {bData}')
    return lstModules

def sendAndRecv(oSock, bData, sendOnly = False):
    oSock.send(bData)
    if sendOnly: return
    return oSock.recv(4096)

def getAccess(oSock, sModule):
    bResponse = sendAndRecv(oSock,'{}\n'.format(sModule).encode())
    if b'AUTH' in bResponse: return False ## No unauthenticated access
    ## For getting files, just use any rsync client at this point
    return True

def getModules(oSock):
    ## This only works unauthenticated
    bResponse = sendAndRecv(oSock, b'\n')
    while True:
        if b'@RSYNCD: EXIT\n' in bResponse: break
        try: bResponse += oSock.recv(4096)
        except TimeoutError: break
    return bResponse

def getBanner(lstArgs):
    (sIP, iPort, boolVerbose) = lstArgs 
    global boolUnauthenticatedAccess
    oSock = socket.socket(socket.AF_INET)
    oSock.settimeout(iTimeout)
    try: oSock.connect((sIP, iPort))
    except TimeoutError: return
    except ConnectionRefusedError: return
    bResp = sendAndRecv(oSock, bOurBanner)
    if not b'SYNC' in bResp: return ## Not an rsync listener
    ## Banner
    sBanner = bResp.decode(errors='ignore')
    sDaemon = sBanner.split(':')[0].replace('@','')
    sVersion = sBanner.split(':')[1].strip().split(' ')[0]
    print(f'[+] Got banner from {sIP}:{iPort} : {sDaemon}, version {sVersion}')
    if boolVerbose: print(f'    Full response from {sIP}:{iPort} : {sBanner}')
    getVulns(sIP, iPort, sVersion)
    ## List modules
    bResponse = getModules(oSock)
    lstModules = parseResponse(f'{sIP}:{iPort}', bResponse, boolVerbose) ## List of tuples "name" / "comment"
    oSock.close() ## Other requests need a new connection
    ## Verify Access to each module
    for lstModule in lstModules:
        oSock = socket.socket(socket.AF_INET)
        oSock.settimeout(iTimeout)
        oSock.connect((sIP, iPort))
        sendAndRecv(oSock, bOurBanner)
        lstData = (sIP, iPort, lstModule[0], lstModule[1], sVersion, getAccess(oSock, lstModule[0]))
        lstTargetModules.append(lstData)
        if lstData[4]: boolUnauthenticatedAccess = True
        print('    System {}:{} has module: {} ({}) {}'.format(lstData[0],lstData[1], lstData[2],lstData[3],'UNAUTHENTICATED' if lstData[5] else '',))
        oSock.close()
    return lstTargetModules ## IP, Port, ModuleName, ModuleComment, VersionNr, UnauthAccess

def main():
    global boolUnauthenticatedAccess
    sUsage = ('usage: %prog [options] SUBNET/ADDRESS/FILE\n'
              'This script performs enumeration of rsync listeners, default TCP/873\n'
              'Last argument should be the target: IP, CIDR or file containing addresses/subnets'
              )
    oParser = optparse.OptionParser(usage=sUsage)
    oParser.add_option('--port', '-p', metavar='INT', help=f'Port to use, default 873', default=873)
    oParser.add_option('--verbose', '-v', action='store_true', help='Verbosity. Default False', default=False)
    (oOptions, lstArgs) = oParser.parse_args()
    iDstPort = int(oOptions.port)
    
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
    #if oOptions.server.split(':')[0] in lstIPs: lstIPs.remove(oOptions.server.split(':')[0])
    print(f'[!] Sending requests to {len(lstIPs)} addresses')
    pool = ThreadPool(64)
    pool.map(getBanner, zip(lstIPs, repeat(iDstPort), repeat(oOptions.verbose)))
    if boolUnauthenticatedAccess: print('[!] Unauthenticated module(s) detected, please use an rsync client for file access')
    return

if __name__ == '__main__':
    main()
