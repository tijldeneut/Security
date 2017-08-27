#!/usr/bin/env python
''' 
	Copyright 2017 Photubias(c)

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

        File name SubnetScanner.py
        written by tijl[dot]deneut[at]howest[dot]be

        Written for Python2.x
        This script tries to find potential subnets on a given network,
        it will look for the usual private subnets.
        It tries to take advantage of the fact that the routers on each subnet
        respond to connections on Port 22 (Cisco) or others ...
'''
import sys, os, socket, struct, argparse
from binascii import hexlify, unhexlify
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat

## Three options for sending syn / receiving syn-ack and then sending reset:
#1. RAW Python Sockets (always available in Python but not possible in Windows)
#2. Directly with pcap (Winpcap, libpcap)
#3. Using Scapy module (takes a lot of time to load the required modules)

## So we use normal sockets and perform three-way handshakes
### Change these in case you're not using arguments
itimeout = 2 # Amount of time to wait for answers (seconds)
subnetsToScan = ['192.168.0.0/16', '172.16.0.0/12']
#subnetsToScan = ['192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8'] ## Want ALL usual private subnets? Uncomment this
scansPerSubnet = [256, 4096] ## This will split subnets above into X equal networks, e.g. 172.16.0.0 and 4096 is 172.16.0.1, 172.16.1.1, 172.16.2.1, ..., 172.31.255.1
#scansPerSubnet = [256, 4096, 65536] ## Want ALL usual private subnet options? Uncoment this
destPort = 22
threads = 256

# Function to be threaded to actually scan one IP
def scanIP(args):
    ip, port = args
    global arrAllResponses
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.settimeout(itimeout)
    try:
        s.connect((ip, port))
    except:
        return False
    l_onoff = 1
    l_linger = 0
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
    s.close()
    arrAllResponses.append(ip)
    print('Response from '+ip)
    return True

def getIPArray(subnet,iScansPerSubnet):
    import math
    def bin2ip(b):
        b = b.zfill(32)
        ip = ""
        for i in range(0,len(b),8):
            ip += str(int(b[i:i+8],2))+"."
        return ip[:-1]

    def dec2bin(n,d=None):
        s = ''
        while n>0:
            if n&1:
                s = '1'+s
            else:
                s = "0"+s
            n >>= 1
        if d is not None:
            while len(s)<d:
                s = "0"+s
        if s == "": s = "0"
        return s
    
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
    
    iHostBits = 32-int(subnet.split("/")[1])
    iAmountOfIPs = int(math.pow(2,iHostBits))
    bStep = dec2bin(iAmountOfIPs / iScansPerSubnet)
    #print('Step is '+bStep)
    
    bFirstIp = (ip2bin(subnet.split("/")[0]))[:-1] + '1'
    #print('First ip is '+bFirstIp)
    
    arrIp = []
    for i in range(0,iScansPerSubnet):
        iStep = int(bStep,2) * i
        arrIp.append(bin2ip(bin(int(bFirstIp,2) + iStep)[2:]))
        #print(bin2ip(bin(int(bFirstIp,2) + iStep)[2:]))

    #print(bin2ip(bin(int(bFirstIp,2) + int(bStep,2))[2:]))
    return arrIp

### The program
## The Banner
print """
[*****************************************************************************]
                        --- Automatic Subnet Scanner ---
         This script tries to find potential subnets on a network,
 it will look for the usual private subnet routers and scan a given TCP Port.

  It supports multiple subnets at once, but only when run without arguments.
      
         -> This script relies on nothing, works on Linux & Windows!
         
                  Example: Arguments -s 172.16.0.0/12 -n 4096
  will result in scanning 172.16.1.1, 172.16.2.1, 172.16.3.1 to 172.31.255.1
  
______________________/-> Created By Tijl Deneut(c) <-\_______________________
[*****************************************************************************]
"""
## Defaults and parsing arguments
parser = argparse.ArgumentParser()
parser.add_argument('-s', help='Provide subnet to scan (CIDR, e.g. 192.168.0.0/16)', default='192.168.0.0/16')
parser.add_argument('-n', help='Amount of IPs to scan, will device the subnet into equal portions. 256 means 192.168.0.1, 192.168.1.1, 192.168.2.1, ..., 192.168.255.1.', default=256, type=int)
parser.add_argument('-t', help='Provide number of threads to use, default is 128', default=128, type=int)
parser.add_argument('-p', help='Which Port to scan for, default is 22?', default=22, type=int)
parser.add_argument('-o', help='Create CSV file with results.', default='')
args = parser.parse_args()

if (len(sys.argv) == 1 or (len(sys.argv) <= 3 and args.o)):
    print('No arguments specified, using built-in values.\n')
else:
    subnetsToScan = [args.s]
    scansPerSubnet = [args.n]
    threads = args.t
    destPort = args.p

## Getting all IPs in one single array
arrAllIps = []
for i in range(0,len(subnetsToScan)):
    arrAllIps.extend(getIPArray(subnetsToScan[i], scansPerSubnet[i]))

print('Ready to scan ' + str(len(arrAllIps)) + ' IP Adresses on TCP Port ' + str(destPort))

if (len(sys.argv) == 1 or (len(sys.argv) <= 3 and args.o)):
    raw_input('Press enter to start ' + str(threads) + ' threads, each waiting ' + str(itimeout) + ' seconds.\n')
else:
    print('Starting ' + str(threads) + ' threads, each waiting ' + str(itimeout) + ' seconds.\n')

arrAllResponses = []

## Threading the scan:
pool = ThreadPool(threads)
pool.map(scanIP, zip(arrAllIps, repeat(destPort)))
arrAllResponses = sorted(arrAllResponses)

if not args.o == '':
    thefile = open(args.o, 'w')
    for x in arrAllResponses:
        thefile.write("%s," % x)

iNumberOfResponses=len(arrAllResponses)
print('Found ' + str(iNumberOfResponses) + ' IP adresses!')
raw_input('Press Enter to show all results, there are no false positives, but not all adresses may be found.\n')
for x in arrAllResponses:
    print(x)
