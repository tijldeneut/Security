#! /usr/bin/python3
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

    This should work on Linux & Windows using Python3
        
    File name cups-fingerprinter.py
    written by Photubias

    --- CUPS Version Fingerprinter ---
    - Uses UDP/631 (CUPS Browsed daemon)
    - It triggers a TCP response to a provided IP address
    - Has a serving component and a scanning component, can be run seperately:
      * Server (run on reachable system): CUPS-Fingerprinter.py -r -s 0.0.0.0:12345 -n
      * Scanner: CUPS-Fingerprinter.py -s 11.22.33.44:12345 192.168.20.0/24
      * Server & Scanner: CUPS-Fingerprinter.py -s 11.22.33.44:12345 -r 192.168.20.0/24
'''
import socket, optparse, os, threading, time
iTimeout= 5
iDstPort = 631
sKeyword = 'CupsAndBalls' ## This is added to the POST request to tie the scanner & server together
lstAllResponses = []

def send_only(s, ip, port, string):
    data = bytes.fromhex(string.encode().hex())
    s.sendto(data, (ip, port))

def recv_only(s):
    data, addr=s.recvfrom(1024)
    return data, addr

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

def parseResponse(sData, boolVerbose):
    lstResponse = sData.split('\n')
    sSource = sVersion = None
    for sLine in lstResponse:
        if not sSource and sKeyword in sLine:
            sSource = sLine.split(f'{sKeyword}_')[1].split(' ')[0]
            if sSource in lstAllResponses: return
            else: lstAllResponses.append(sSource)
        if 'User-Agent' in sLine: sVersion = sLine.split('User-Agent: ')[1]
    if boolVerbose: print(sData)
    if sSource and sVersion: print(f'[+] Success, system with IP {sSource} has CUPS version: {sVersion}')
    return

def runServer(sIP, iPort, boolVerbose):
    oServSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        oServSock.bind((sIP, iPort))
        oServSock.listen(iTimeout)
        print(f'[+] Started listener on {sIP}:{iPort}\n    Press Ctrl+Break (Ctrl+F6) to stop')
        while True:
            oClientSock, address = oServSock.accept()
            bData = b''
            while True:
                bDatapart = oClientSock.recv(1024)
                bData += bDatapart
                if len(bDatapart) < 1024: break
            sRequest = bData.decode('utf-8', errors='ignore')
            parseResponse(sRequest, boolVerbose)
            oClientSock.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nThank you\r\n')
            oClientSock.close()
    except Exception as e: print(f'[-] Error: {e}')
    finally: oServSock.close()
    return

def sendCUPS(sIP, iPort, sServer, boolVerbose):
    oSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    oSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    oSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    oSock.settimeout(iTimeout)
    sData = f'0 3 http://{sServer}/printers/{sKeyword}_{sIP}'
    if boolVerbose: print(f'[+] Sending to {sIP}:{iPort}')
    send_only(oSock, sIP, iPort, sData)
    oSock.close()
    return

def main():
    sUsage = ('usage: %prog [options] SUBNET/ADDRESS/FILE\n'
              'This script performs threaded enumeration of CUPS Browsed listeners on UDP 631\n'
              'Requires a reachable listener, run this script as server-only or some generic NetCat one\n'
              'Last argument should be the target: IP, CIDR or file containing addresses/subnets\n'
              'Server-only: %prog -s 192.168.50.10:80 -n -r\n'
              'Scanner-only: %prog -s 192.168.50.10:80 10.11.12.0/24\n'
              'Server & Scanner: %prog -s 192.168.50.10:80 -r 10.11.12.0/24'
              )
    oParser = optparse.OptionParser(usage=sUsage)
    oParser.add_option('--server', '-s', metavar='STRING', help='Provide HTTP Server details like this IP:PORT, always required')
    oParser.add_option('--runserver', '-r', action='store_true', help='Start the listening HTTP server locally, default False', default=False)
    oParser.add_option('--noscan', '-n', action='store_true', help='Do no perform the scan, useful for listening only', default=False)
    oParser.add_option('--verbose', '-v', action='store_true', help='Verbosity. Default False', default=False)
    (oOptions, lstArgs) = oParser.parse_args()
    if not oOptions.server or not ':' in oOptions.server: 
        print('[-] Error, please provide at least the listening endpoint details in the form IP:PORT')
        exit()
    boolServe = True if oOptions.runserver == True else False
    boolScan = False if oOptions.noscan == True else True

    if boolServe:
        oServerThread = threading.Thread(target=runServer, args=(oOptions.server.split(':')[0], int(oOptions.server.split(':')[1]), oOptions.verbose))
        oServerThread.start()
        time.sleep(1)
    if boolScan:
        if not lstArgs or not len(lstArgs) == 1:
            sCIDR = input('[?] Please enter the subnet or IP to scan [192.168.50.0/24] : ')
            if sCIDR == '': sCIDR = '192.168.50.0/24'
            lstIPs = getIPs(sCIDR)
        elif boolScan:
            if os.path.isfile(lstArgs[0]):
                print('[+] Parsing file {} for IP addresses/networks.'.format(lstArgs[0]))
                lstIPs = getIPsFromFile(lstArgs[0])
            else: 
                lstIPs = getIPs(lstArgs[0])
        if oOptions.server.split(':')[0] in lstIPs: lstIPs.remove(oOptions.server.split(':')[0])
        print(f'[!] Sending requests to {len(lstIPs)} addresses')
        for sIP in lstIPs: sendCUPS(sIP, iDstPort, oOptions.server, oOptions.verbose)
    if boolServe: print('[!] Hold on, waiting for responses ...')
    return

if __name__ == '__main__':
    main()
