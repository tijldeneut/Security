#! /usr/bin/python3
# -*- coding: utf-8 -*- 
'''
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
        Only requires "pip install requests"
        
        File name iDRAC-fingerprinter.py
        written by Photubias

        --- Dell iDRAC Fingerprinter ---
        integrated Dell Remote Access Controller
        This script tries to detect the iDRAC version, currently only works for iDRAC8 & iDRAC9
        --> If more are available for a test, they will be added

        
'''
import optparse, requests, json, datetime, os
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

iTimeout = 10

dicHeaders = {'User-Agent' : r'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36', 'Content-Type': 'application/json'}
sExportFileName = '{}-iDRACs.txt'.format(datetime.datetime.now().strftime(r'%Y%m%d-%H%M%S'))
_lstToWrite = []

def fingerPrint(listArgs):
    (sIP, boolVerbose, sProxy, boolVulns, boolExport) = listArgs
    global _lstToWrite
    def getPage(sURL):
        try:
            if sProxy: oResponse = requests.get(sURL, verify=False, proxies={'https':sProxy}, headers = dicHeaders, timeout = iTimeout)
            else: oResponse = requests.get(sURL, verify=False, headers = dicHeaders, timeout = iTimeout)
            return oResponse
        except:
            return None
        
    def getBMCInfo(sResult):
        lstLines = sResult.split('\n')
        for sLine in lstLines:
            if 'var BMC_INFO' in sLine: return sLine.split('"')[1]
        return ''

    def getFWViaRedfish(sURL):
        ## This endpoints requires auth: '/redfish/v1/Managers/iDRAC.Embedded.1/Attributes?$select=Info.*'
        oResponse = getPage(sURL + '/redfish/v1/Registries/ManagerAttributeRegistry/ManagerAttributeRegistry.v1_0_0.json')
        oJson = json.loads(oResponse.text)
        return oJson['SupportedSystems'][0]['FirmwareVersion']

    ## Currently only iDRAC 8 & iDRAC 9 supported
    sURL = 'https://' + sIP
    #if boolVerbose: print(f'[!] Scanning URL {sURL}')
    ## iDRAC 8 attempt
    oResponse = getPage(sURL + '/locale/locale_en.json')
    if oResponse and oResponse.status_code == 200:
        sResult = oResponse.text
        oJson = json.loads(sResult)
        if oJson['localeString']['gen_iDrac8']:
            oResponse = getPage(sURL + '/session?aimGetProp=hostname,gui_str_title_bar,OEMHostName,fwVersion,sysDesc')
            if oResponse:
                oJson = json.loads(oResponse.text)['aimGetProp']
                if boolVerbose: print(oJson)
                sHostname = oJson['hostname']
                sFWversion = oJson['fwVersion']
                sSystem = oJson['sysDesc']
                if boolExport: _lstToWrite.append(f'{sIP};iDRAC8;{sSystem};{sHostname};{sFWversion}\n')
                print('[+] {}: {} ({}, iDRAC8, Firmware v{})'.format(sIP, sHostname, sSystem, sFWversion))
                if boolVulns: getVulns(sHostname, 'iDRAC8', sFWversion, sIP, sSystem)
                return

    ## iDRAC 9 attempt
    oResponse = getPage(sURL + '/restgui/locale/strings/locale_str_en.json')
    if oResponse and oResponse.status_code == 200:
        oJson = json.loads(oResponse.text)
        if oJson['app_title'] == 'iDRAC9':
            oResponse = getPage(sURL + '/restgui/js/services/resturi.js')
            sResult = oResponse.text
            sEndpoint = getBMCInfo(sResult)
            oResponse = getPage(sURL + sEndpoint)
            oJson = json.loads(oResponse.text)['Attributes']
            if boolVerbose: print(oJson)
            sHostname = oJson['iDRACName']
            if not 'FwVer' in oJson: sFWversion = getFWViaRedfish(sURL)
            else: sFWversion = oJson['FwVer']
            sSystem = oJson['SystemModelName']
            sLicense = oJson['License']
            if boolExport: _lstToWrite.append(f'{sIP};iDRAC9 {sLicense};{sSystem};{sHostname};{sFWversion}\n')
            print('[+] {}: {} ({}, iDRAC9 {}, Firmware v{})'.format(sIP, sHostname, sSystem, sLicense, sFWversion))
            if boolVulns: getVulns(sHostname, 'iDRAC9 {}'.format(sLicense), sFWversion, sIP, sSystem)
            return

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

def verifyCVE_2018_1207(sIP, boolExploit = False, sProxy = None):
    ## TODO: Based on : https://github.com/KraudSecurity/Exploits/blob/master/CVE-2018-1207/CVE-2018-1207.py
    sURL = f'https://{sIP}/cgi-bin/login?LD_DEBUG=files'
    dicNewHeaders = dicHeaders
    dicNewHeaders['Accept'] = ''
    if sProxy: oResponse = requests.get(sURL, verify=False, proxies={'https':sProxy}, headers = dicHeaders, timeout = iTimeout)
    else: oResponse = requests.get(sURL, verify=False, headers = dicHeaders, timeout = iTimeout)
    if 'calling init: /lib/' in oResponse.text: print(f'  [!!] {sIP} is definitely vulnerable and can easily be exploited: {sURL}')
    return

def getIPsFromFile(sFile):
    lstLines = open(sFile,'r').read().splitlines()
    lstIPs = []
    for sLine in lstLines: ## Line can be an IP or a CIDR
        for sIP in getIPs(sLine): lstIPs.append(sIP)
    return lstIPs

### Vuln checking based on buildnumbers
def getVulns(sName, sVersion, sFWversion, sIP, sSystem): ##sHostname, 'iDRAC9 {}'.format(sLicense), sFWversion, sIP, sSystem
    ##  sName = server-hostname
    ##  sVersion = iDRAC 9 (optionally includes "Enterprise")
    ##  sFWversion = 2.52.52.52
    ##  sIP = 192.168.0.1
    ##  sSystem = PowerEdge R630
    ## CVE-2018-1207, vulnerable firmware iDRAC7 or iDRAC8, firmware < 2.52.52.52
    sVuln = '  [!] ' + sIP + ' is vulnerable to CVE-2018-1207, Code Injection Vulnerability (RCE)'
    boolCVE20181207 = False
    if '8' in sVersion or '7' in sVersion:
        if int(sFWversion.split('.')[0])>2: return
        elif int(sFWversion.split('.')[1])>52: return
        else: 
            print(sVuln)
            boolCVE20181207 = True
    if boolCVE20181207: verifyCVE_2018_1207(sIP, boolExploit=False)
    return

def writeFile(lstToWrite, sFilename):
    with open(sFilename,'w') as oFile:
        for sLine in lstToWrite:
            oFile.write(sLine+'\n')
        oFile.close()
    print('[+] Created file {} containing all {} responsive IP addresses, feel free to run the IPMI scanner.'.format(sFilename, len(lstToWrite)))
    return

def main():
    sUsage = ('usage: %prog [options] SUBNET/ADDRESS/FILE\n'
              'This script performs enumeration of iDRAC systems on a given subnet or IP\n'
              'When provided with the --scanvulns parameter it spits out critical vulns based on the Firmware version.\n\n'
              'This script is 100% OPSEC safe (unless you decide to exploit)!')
    parser = optparse.OptionParser(usage = sUsage)
    parser.add_option('--threads', '-t', metavar='INT', dest='threads', default = 64, help='Amount of threads. Default 64')
    parser.add_option('--scanvulns', '-s', dest='vulns', action='store_true', help='Check for common vulns.', default=False)
    parser.add_option('--proxy', '-p', metavar='STRING', dest='proxy', help='HTTP proxy (e.g. 127.0.0.1:8080), optional')
    parser.add_option('--export', '-e', dest='export', action='store_true', help='Create list of addresses running iDRAC. Default False', default=False)
    parser.add_option('--verbose', '-v', dest='verbose', action='store_true', help='Verbosity. Default False', default=False)
    (options,args) = parser.parse_args()
    if not args or not len(args) == 1:
        sCIDR = input('[?] Please enter the subnet or IP to scan [192.168.50.0/24] : ')
        if sCIDR == '': sCIDR = '192.168.50.0/24'
        lstIPs = getIPs(sCIDR)
    else:
        if os.path.isfile(args[0]):
            print('[+] Parsing file {} for IP addresses/networks.'.format(args[0]))
            lstIPs = getIPsFromFile(args[0])
        else: 
            lstIPs = getIPs(args[0])
    oPool = ThreadPool(int(options.threads))
    print('[!] Scanning {} addresses using up to {} threads.'.format(len(lstIPs), options.threads))
    oPool.map(fingerPrint, zip(lstIPs, repeat(options.verbose), repeat(options.proxy), repeat(options.vulns), repeat(options.export)))
    if options.export: writeFile(_lstToWrite, sExportFileName)
    return

if __name__ == "__main__":
    main()
