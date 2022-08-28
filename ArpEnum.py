#! /usr/bin/env python3

# Enumerate hosts on local network via IPv4 ARP
# Works on both Linux and Windows, but requires python3 -m pip install scapy
# Example usages:
#  ArpEnum.py 192.168.1.0/24 eth0
#  ArpEnum.py 192.168.0.0/16 Ethernet
#  ArpEnum.py 172.16.0.0/12 ens192
#  ArpEnum.py 10.0.0.0/8 "Local Network"

from scapy.all import get_if_list, Ether, ARP, conf, AsyncSniffer, time, sendp
import os, ipaddress, sys
if os.name=='nt': from scapy.all import get_windows_if_list
conf.layers.filter([ARP])
sInt = sMynet = ''

def selectInterface():
    if os.name=='nt':
        counter = 0
        arrInterfaces = get_windows_if_list()
        for arrInt in arrInterfaces:
            sIPv4 = ''
            for sIP in arrInt['ips']:
                if len(sIP.split('.')) == 4: sIPv4 = sIP
            print('['+str(counter)+'] ' + sIPv4 + ': ' + arrInt['name'] + ' (' + arrInt['description'] + ')')
            arrInterfaces[counter] = arrInterfaces[counter]['name']
            counter += 1
    else:
        counter = 0
        arrInterfaces = get_if_list()
        for sInt in arrInterfaces:
            if not sInt == 'lo':
                print('[' + str(counter) + ']: ' + sInt)
                counter += 1
            else:
                arrInterfaces.remove(sInt)
        if(len(arrInterfaces)==1): return arrInterfaces[0]
    print('[Q] Quit')
    sAnsw = input('Select interface [0]: ')
    if sAnsw.lower()[0] == 'q': exit()
    if sAnsw == '' or not sAnsw.isdigit(): sAnsw = '0'
    return arrInterfaces[int(sAnsw)]

if len(sys.argv) != 3:
    print('Enumerate hosts on local subnet(s)')
    print('Usage information:')
    print('  ' + sys.argv[0] + ' <ip or subnet> <interface>')
    print('Example:')
    print('  ' + sys.argv[0] + ' 192.168.0.0/24 eth0')
    print('#'*50)
    ## Select the right interface (or ask it)
    sInt = selectInterface()
    ## Ask for the Subnet
    sMynet = input('Please enter the subnet-to-scan [192.168.0.0/24]: ')
    if sMynet == '': sMynet = '192.168.0.0/24'
else: 
    sMynet=sys.argv[1]
    sInt=sys.argv[2]

## Show info
iAddressCount = len([str(ip) for ip in ipaddress.IPv4Network(sMynet)])
print('[!] Scanning ' + sMynet + ' ('+str(iAddressCount)+' IP\'s)')
## Start sniffer in separate thread
arrResponses = []
oSniffer = AsyncSniffer(prn=lambda x: arrResponses.append(x), store=False, filter="arp and arp[6:2] == 2")
oSniffer.start()
## Send all packets
sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst = sMynet), iface = sInt, verbose = False)
print('[!] Waiting 2 seconds for the responses to find their way back')
time.sleep(2)
oSniffer.stop()
## Parsing
arrLiveSystems = []
arrMacList = []
for arrReceived in arrResponses:
    sMac = arrReceived.hwsrc
    sIP = arrReceived.psrc
    if sMac not in arrMacList:
        print(arrReceived.summary().replace(' / Padding',''))
        arrMacList.append(sMac)
        arrLiveSystems.append((sMac,sIP))
if len(arrLiveSystems) == 0: print('[-] No systems found for network ' + sMynet)
else: print('[+] Found ' + str(len(arrLiveSystems)) + ' IP address(es) on network ' + sMynet)
if len(sys.argv) != 3: input('Press enter to close')

'''
## Replaces the GUID in 'get_windows_if_list()' with the NPF devicename and only the usable interfaces
def getWindowsInterfaces():
    arrWinInterfaces = []
    for arrInt in get_windows_if_list():
        for sNPF in get_if_list():
            sNPFGuid = None
            if '{' in sNPF: sNPFGuid = sNPF.split('{')[1].split('}')[0]
            if sNPFGuid and sNPFGuid in arrInt['guid']:
                arrInt['guid'] = sNPF
                arrWinInterfaces.append(arrInt)
    return arrWinInterfaces

arrWinInterfaces = getWindowsInterfaces()
counter = 0
for arrIface in arrWinInterfaces:
    counter += 1
    print('Select your interface')
    if arrIface['name'] == 'Ethernet':
        sNPFName = arrIface['guid']
'''
