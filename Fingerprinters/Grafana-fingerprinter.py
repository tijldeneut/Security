#!/usr/bin/env python3
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
        Only requires "pip install requests"
        
        File name Grafana-fingerprinter.py
        written by Photubias

        --- Grafana Fingerprinter ---
        This script tries to detect the exact Grafana version 
         based on the json embedded in the login page
'''

import optparse, requests, os, json, re
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

iTimeout = 5

def getIPsFromFile(sFile):
    lstLines = open(sFile,'r').read().splitlines()
    lstIPs = []
    for sLine in lstLines: ## Line can be an IP or a CIDR or a hostname
        for sIP in getIPs(sLine): lstIPs.append(sIP)
    return lstIPs

def fingerPrint(listArgs): ## sTarget = either IP or FQDN
    (sTarget, boolVerbose, sProxy, iPort, boolNovulns) = listArgs
    sVersion = sLatestVersion = None
    if iPort: sURL = f'http://{sTarget}:{iPort}/login'
    else: sURL = f'http://{sTarget}/login'
    try:
        if sProxy: oResponse = requests.get(sURL, verify=False, proxies={'https':sProxy}, stream=True)
        else: oResponse = requests.get(sURL, verify=False, stream=True)
    except:
        if iPort: sURL = f'https://{sTarget}:{iPort}/login'
        else: sURL = f'https://{sTarget}/login'
        try: 
            if sProxy: oResponse = requests.get(sURL, verify=False, proxies={'https':sProxy}, stream=True)
            else: oResponse = requests.get(sURL, verify=False, stream=True)
        except: 
            if boolVerbose: print(f'[-] {sTarget}:{iPort} is unresponsive')
            return
    if not oResponse.status_code == 200: return
    sResponse = oResponse.text
    ## Three options to get version here: all in "grafanaBootData"
    if not 'window.grafanaBootData' in sResponse: return
    sRegex = r'window.grafanaBootData\s*=\s*(\{.*?\});'
    oJson = re.search(sRegex, sResponse, re.DOTALL)
    if oJson:
        sJson = oJson.group(1)
        ## Not a real Json (encoding), fixing this:
        sJson = re.sub(r'([{,]\s*)([a-zA-Z0-9_]+)\s*:', r'\1"\2":', sJson)
        sJson = re.sub(r'\'', r'"', sJson)
        dctJson = json.loads(sJson)
        if 'settings' in dctJson and 'buildInfo' in dctJson['settings']:
            sVersion = dctJson['settings']['buildInfo']['version']
            sLatestVersion = dctJson['settings']['buildInfo']['latestVersion']
        elif 'navTree' in dctJson and len(dctJson['navTree']) > 1 and dctJson['navTree'][1]['id'] == 'help':
            sVersion = dctJson['navTree'][1]['subTitle'].replace('Grafana ').replace(' ')[0]
    else: return
    print(f'[+] System {sURL.replace('/login','')} is running Grafana version {sVersion}')
    if not boolNovulns: getVulns(sVersion, sURL.replace('/login',''), boolVerbose)
    return

def getIPs(sCIDR): ## Could also be a single hostname
    import ipaddress
    try: lstIPs = [str(sTarget) for sTarget in list(ipaddress.ip_network(sCIDR, False).hosts())]
    except: ## Not an IP address but a hostname
        lstIPs = [sCIDR.replace('http://','').replace('https://','').split(':')[0]]
    return lstIPs

### Vuln checking based on buildnumbers
def getVulns(sVersion, sTarget, boolVerbose):
    if boolVerbose: print(f'[i] Listing vulnerabilities for {sTarget} (Grafana v{sVersion})')
    iMajor = int(sVersion.split('.')[0])
    iMinor = int(sVersion.split('.')[1])
    if len(sVersion.split('.')) <= 2: iBuild = 0
    else: iBuild = int(sVersion.split('.')[2])
    ## CVE-2024-9264: RCE if DuckDB is used (https://grafana.com/blog/2024/10/17/grafana-security-release-critical-severity-fix-for-cve-2024-9264/)
    ### Fixed in 11.0.6, 11.1.7, 11.2.2
    sVuln = f'  [!!] {sTarget} may be vulnerable to CVE-2024-9264: RCE/LFI if DuckDB is configured in backend'
    if iMajor == 11 and iMinor == 0 and iBuild < 6: print(sVuln)
    elif iMajor == 11 and iMinor == 1 and iBuild < 7: print(sVuln)
    elif iMajor == 11 and iMinor == 2 and iBuild < 2: print(sVuln)
    return
    
def main():
    sUsage = ('usage: %prog [options] SUBNET/ADDRESS/FILE\n'
              'This script performs enumeration of Grafana systems on a given subnet, IP or file\n'
              'Default port is 3000, it will scan http & https for each of the addresses given\n'
              'The --novulns parameter enables to not show potential vulnerabilities, done purely based on the version.\n\n'
              'This script is 100% OPSEC safe')
    parser = optparse.OptionParser(usage = sUsage)
    parser.add_option('--threads', '-t', metavar='INT', dest='threads', default = 128, help='Amount of threads. Default 128')
    parser.add_option('--novulns', '-n', dest='novulns', action='store_true', help='Check for common vulns, critical only', default=False)
    parser.add_option('--port', '-p', metavar='INT', dest='port', default = 3000, help='HTTP port. Default 3000, optional')
    parser.add_option('--proxy', metavar='STRING', dest='proxy', help='HTTP proxy (e.g. 127.0.0.1:8080), optional')
    parser.add_option('--verbose', '-v', dest='verbose', action='store_true', help='Verbosity. Default False', default=False)
    (options,lstArgs) = parser.parse_args()
    iPort = int(options.port)
    if iPort == 443 or iPort == 80: iPort = None
    if not lstArgs or not len(lstArgs) == 1:
        sCIDR = input('[?] Please enter the subnet or IP to scan [192.168.50.0/24] : ')
        if sCIDR == '': sCIDR = '192.168.50.0/24'
        lstIPs = getIPs(sCIDR)
    else:
        if os.path.isfile(lstArgs[0]):
            print(f'[+] Parsing file {lstArgs[0]} for IP addresses/networks.')
            lstIPs = getIPsFromFile(lstArgs[0])
        else:
            sCIDR = lstArgs[0]
            lstIPs = getIPs(sCIDR)
    
    oPool = ThreadPool(int(options.threads))
    print(f'[!] Scanning {len(lstIPs)} addresses using up to {options.threads} threads.')
    oPool.map(fingerPrint, zip(lstIPs, repeat(options.verbose), repeat(options.proxy), repeat(options.port), repeat(options.novulns)))

if __name__ == '__main__':
    main()
    exit()
