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
        Only requires "pip install requests"
        
        File name Zabbix-fingerprinter.py
        written by Photubias

        --- Zabbix Fingerprinter ---
        Zabbix Web Interface
        This script tries to detect the Zabbix version, tested on v2.0.9 up to v7.0.4
        Requires the PHP file to be available (default 'api_jsonrpc.php')
        --> If more are available for a test, they will be added
'''

import requests, optparse, os
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat
requests.packages.urllib3.disable_warnings()
boolHTTPSOnly = True    ## Set false to add both http & https to the addresses (when not specified)

def getURLsFromFile(sFile):
    lstLines = open(sFile,'r').read().splitlines()
    lstURLs = []
    for sLine in lstLines: ## Line can be an IP, a CIDR or a URL
        for sURL in getURLs(sLine): lstURLs.append(sURL)
    return lstURLs

def getURLs(sData):
    lstURLs = []
    if not 'http' in sData.lower() and '/' in sData:
        ## Probably CIDR
        lstIPs = getIPs(sData)
        for sIP in lstIPs:
            lstURLs.append(f'https://{sIP}')
            if not boolHTTPSOnly: lstURLs.append(f'http://{sIP}')
    elif not '/' in sData:
        ## Probably a single IP or hostname
        lstURLs.append(f'https://{sData.lower()}')
        if not boolHTTPSOnly: lstURLs.append(f'http://{sData.lower()}')
    elif 'http' in sData.lower():
        ## Full URL
        if sData[-1:] == '/': sData = sData[:-1]
        lstURLs.append(sData.lower())
    return lstURLs

def getIPs(sCIDR):
    import ipaddress
    return [str(sIP) for sIP in list(ipaddress.ip_network(sCIDR, False).hosts())]

def fingerPrint(lstArgs):
    (sHost, sEndpoint, boolVerbose, lstProxy, boolVulns) = lstArgs
    oSession = requests.session()
    oSession.verify = False
    sAPIURL = f'{sHost}/{sEndpoint}'
    ## Verify Connection
    try: oResponse = oSession.get(sAPIURL, timeout=5, proxies=lstProxy)
    except: return False
    if oResponse.status_code == 200:
        if boolVerbose: print(f'[-] Not normal getting a HTTP/200 on API page {sAPIURL}, honeypot maybe?')
        return False
    elif oResponse.status_code == 404:
        if boolVerbose: print(f'[-] Error 404, endpoint {sAPIURL} does not exist!')
        return False
    elif not (oResponse.status_code == 412 or oResponse.status_code == 403): ## 412 is "PreCondition" (older zabbix), 403 is "Forbidden" (newer Zabbix)
        if boolVerbose: print(f'[-] Error {oResponse.status_code} on endpoint {sAPIURL}')
        return False
    ## Get Zabbix version
    oSession.headers.update({'Content-Type':'application/json-rpc'})
    lstData={'jsonrpc':'2.0','method':'apiinfo.version','params':{},'id':1}
    oResponse = oSession.post(sAPIURL,json=lstData, proxies=lstProxy)
    if oResponse.status_code==200:
        lstResponse = oResponse.json()
        print(f'[+] Detected Zabbix version {lstResponse['result']} on {sHost}')
        if boolVulns: getVulns(sHost, lstResponse['result'])
    return

def getVulns(sHost, sVersion):
    ### Assumption: sVersion is always 3 digits: 1.2.3
    iMajor = int(sVersion.split('.')[0])
    iMinor = int(sVersion.split('.')[1])
    iBuild = int(sVersion.split('.')[2])
    ## CVE-2024-42327: Authenticated SQLi in the API endpoint (https://support.zabbix.com/browse/ZBX-25623)
    ## Vulnerable are 6.0.0-6.0.31, 6.4.0-6.4.16 and 7.0.0
    sVuln = f'    [!!] {sHost} is vulnerable to CVE-2024-42327 and exploitable: Authenticated SQLi in the API endpoint'
    if iMajor == 7 and iMinor == 0 and iBuild == 0: print(sVuln)
    elif iMajor == 6 and iMinor == 4 and iBuild <= 16: print(sVuln)
    elif iMajor == 6 and iMinor == 0 and iBuild <= 31: print(sVuln)
    return

def main():
    sUsage = ('usage: %prog [options] SUBNET/ADDRESS/FILE/URL\n'
              'This script performs enumeration of Zabbix systems on a given subnet, IP or file\n'
              'When provided with the --vulns parameter it spits out vulns based on the buildnr.\n\n'
              'This script is 100% OPSEC safe!')
    oParser = optparse.OptionParser(usage = sUsage)
    oParser.add_option('--threads', '-t', metavar='INT', dest='threads', default = 64, help='Amount of threads. Default 64')
    oParser.add_option('--vulns', '-v', dest='vulns', action='store_true', help='Check for common vulns.', default=False)
    oParser.add_option('--proxy', '-p', metavar='STRING', dest='proxy', help='HTTP proxy (e.g. 127.0.0.1:8080), optional')
    oParser.add_option('--endpoint', '-e', metavar='STRING', dest='endpoint', help='overwrite API page, default "api_jsonrpc.php", optional', default='api_jsonrpc.php')
    oParser.add_option('--verbose', dest='verbose', action='store_true', help='Verbosity. Default False', default=False)
    (oOptions, lstArgs) = oParser.parse_args()
    lstProxy = {} if not oOptions.proxy else {'http':oOptions.proxy,'https':oOptions.proxy}
    if not lstArgs or not len(lstArgs) == 1:
        sAns = input('[?] Please enter the subnet, IP or URL to scan [https://192.168.50.1] : ')
        if sAns == '': sAns = 'https://192.168.50.1'
        lstURLs = getURLs(sAns)
    else:
        if os.path.isfile(lstArgs[0]):
            print(f'[+] Parsing file {lstArgs[0]} for IP addresses/networks.')
            lstURLs = getURLsFromFile(lstArgs[0])
        else:
            lstURLs = getURLs(lstArgs[0])

    oPool = ThreadPool(int(oOptions.threads))
    print(f'[!] Scanning {len(lstURLs)} addresses using up to {oOptions.threads} threads.')
    oPool.map(fingerPrint, zip(lstURLs, repeat(oOptions.endpoint), repeat(oOptions.verbose), repeat(lstProxy), repeat(oOptions.vulns)))

if __name__ == '__main__':
    main()
