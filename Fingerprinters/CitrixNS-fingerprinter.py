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

        Scanning based on https://github.com/fox-it/citrix-netscaler-triage
        
        File name CitrixNS-fingerprinter.py
        written by Photubias

        --- Citrix NS Fingerprinter ---
        This script tries to detect the exact NetScaler version 
         based on the timestamp embedded in the header of a small gz-file
        TODO: When the '-v' parameter is added, vulnerabilities are printed too

        ## INFO:
        # CVE-2023-4966 (CitrixBleed) Unauthenticated infodumper (https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX579459)
        #   When configured as a VPN, Proxy or AAA server
        #   Exploit: https://github.com/Chocapikk/CVE-2023-4966
        #   fixed in Netscaler 14.1-8.50
        #   fixed in Netscaler 13.1-49.15
        #   fixed in Netscaler 13.0-92.19
        #   fixed in Netscaler 12.1-55.300
        #   fixed in Netscaler 13.1-37.164 (FIPS version)
        #   Older versions also vulnerable
        # CVE-2025-5777 (CitrixBleed 2) Unauthenticated infodumper (https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420)
        #   When configured as a VPN, Proxy or AAA server
        #   Exploit: https://github.com/win3zz/CVE-2025-5777
        #   fixed in Netscaler 14.1-43.56
        #   fixed in Netscaler 13.1-58.32
        #   fixed in Netscaler 13.0-37.235
        #   fixed in Netscaler 12.1-55.328
        #   Older versions also vulnerable
'''

import optparse, requests, os, datetime, csv
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

iTimeout = 5
CITRIX_NETSCALER_VERSION_CSV = r'''
rdx_en_date,rdx_en_stamp,version
2018-08-25 03:29:12+00:00,1535167752,12.1-49.23
2018-10-16 17:54:20+00:00,1539712460,12.1-49.37
2018-11-28 08:56:26+00:00,1543395386,12.1-50.28
2019-01-18 17:41:34+00:00,1547833294,12.1-50.31
2019-02-27 09:30:02+00:00,1551259802,12.1-51.16
2019-03-25 22:37:08+00:00,1553553428,12.1-51.19
2019-05-13 17:41:47+00:00,1557769307,13.0-36.27
2019-09-10 07:54:45+00:00,1568102085,13.0-41.20
2019-10-11 13:24:36+00:00,1570800276,13.0-41.28
2019-11-05 05:18:47+00:00,1572931127,12.1-55.13
2019-11-28 19:06:22+00:00,1574967982,13.0-47.22
2020-01-20 12:46:27+00:00,1579524387,12.1-55.18
2020-01-20 13:09:05+00:00,1579525745,13.0-47.24
2020-02-28 14:27:56+00:00,1582900076,12.1-55.24
2020-03-19 17:40:43+00:00,1584639643,13.0-52.24
2020-03-29 09:10:32+00:00,1585473032,12.1-56.22
2020-06-01 06:48:41+00:00,1590994121,13.0-58.30
2020-06-09 19:06:55+00:00,1591729615,12.1-57.18
2020-07-02 16:38:13+00:00,1593707893,13.0-58.32
2020-07-22 19:49:27+00:00,1595447367,13.0-61.48
2020-09-01 11:47:01+00:00,1598960821,12.1-58.15
2020-09-01 16:14:56+00:00,1598976896,13.0-64.35
2020-09-22 01:21:45+00:00,1600737705,12.1-59.16
2020-10-07 16:07:09+00:00,1602086829,13.0-67.39
2020-10-08 09:03:02+00:00,1602147782,12.1-55.190
2020-11-13 12:56:30+00:00,1605272190,13.0-67.43
2020-12-03 05:13:26+00:00,1606972406,13.0-71.40
2020-12-26 19:04:08+00:00,1609009448,13.0-71.44
2020-12-26 19:39:25+00:00,1609011565,12.1-60.19
2021-01-04 03:07:45+00:00,1609729665,12.1-55.210
2021-02-02 13:36:06+00:00,1612272966,12.1-61.18
2021-02-18 18:37:49+00:00,1613673469,13.0-76.29
2021-03-08 17:23:41+00:00,1615224221,12.1-61.19
2021-03-09 09:20:39+00:00,1615281639,13.0-76.31
2021-03-11 15:46:10+00:00,1615477570,12.1-61.19
2021-04-05 14:13:22+00:00,1617632002,13.0-79.64
2021-05-10 14:38:02+00:00,1620657482,12.1-62.21
2021-05-17 15:56:11+00:00,1621266971,12.1-62.23
2021-05-31 14:05:18+00:00,1622469918,13.0-82.41
2021-06-10 19:21:20+00:00,1623352880,13.0-82.42
2021-06-10 23:39:05+00:00,1623368345,12.1-62.25
2021-07-07 01:45:38+00:00,1625622338,12.1-62.27
2021-07-16 16:45:56+00:00,1626453956,13.0-82.45
2021-09-10 07:31:30+00:00,1631259090,13.1-4.43
2021-09-27 14:01:20+00:00,1632751280,13.0-83.27
2021-10-13 08:24:09+00:00,1634113449,12.1-63.22
2021-11-11 14:42:53+00:00,1636641773,13.1-4.44
2021-11-11 17:02:35+00:00,1636650155,13.0-83.29
2021-11-11 20:06:47+00:00,1636661207,12.1-63.23
2021-11-17 15:43:23+00:00,1637163803,13.1-9.60
2021-12-10 16:17:15+00:00,1639153035,13.1-12.50
2021-12-10 18:48:29+00:00,1639162109,13.0-84.10
2021-12-22 09:54:58+00:00,1640166898,12.1-63.24
2021-12-22 15:18:49+00:00,1640186329,13.0-84.11
2021-12-23 08:28:43+00:00,1640248123,13.1-12.51
2022-01-20 02:36:41+00:00,1642646201,12.1-64.16
2022-01-28 06:22:15+00:00,1643350935,12.1-55.265
2022-02-21 12:49:29+00:00,1645447769,13.1-17.42
2022-03-10 15:17:42+00:00,1646925462,13.0-85.15
2022-04-03 05:18:28+00:00,1648963108,12.1-55.276
2022-04-07 06:11:44+00:00,1649311904,13.1-21.50
2022-04-21 07:34:34+00:00,1650526474,12.1-55.278
2022-04-21 10:38:48+00:00,1650537528,12.1-64.17
2022-04-22 19:18:31+00:00,1650655111,12.1-65.15
2022-05-19 08:10:13+00:00,1652947813,13.0-85.19
2022-05-26 12:51:09+00:00,1653569469,13.1-24.38
2022-06-14 17:03:48+00:00,1655226228,13.0-86.17
2022-06-29 13:46:08+00:00,1656510368,12.1-65.17
2022-07-06 08:54:42+00:00,1657097682,12.1-55.282
2022-07-06 10:41:43+00:00,1657104103,13.1-27.59
2022-07-29 17:39:52+00:00,1659116392,13.0-87.9
2022-08-24 14:57:01+00:00,1661353021,13.1-30.52
2022-09-23 18:53:35+00:00,1663959215,13.1-33.47
2022-10-04 16:11:03+00:00,1664899863,12.1-65.21
2022-10-12 07:25:44+00:00,1665559544,12.1-55.289
2022-10-12 17:01:28+00:00,1665594088,13.1-33.49
2022-10-14 17:10:45+00:00,1665767445,13.0-88.12
2022-10-31 15:54:59+00:00,1667231699,13.0-88.13
2022-10-31 16:31:43+00:00,1667233903,13.1-33.51
2022-11-03 05:22:05+00:00,1667452925,13.0-88.14
2022-11-03 05:38:29+00:00,1667453909,13.1-33.52
2022-11-17 09:55:40+00:00,1668678940,13.1-33.54
2022-11-17 10:37:18+00:00,1668681438,13.0-88.16
2022-11-23 11:42:31+00:00,1669203751,13.1-37.38
2022-11-28 11:55:05+00:00,1669636505,12.1-55.291
2022-11-30 11:42:25+00:00,1669808545,12.1-65.25
2022-12-14 15:54:39+00:00,1671033279,13.0-89.7
2023-01-24 17:44:35+00:00,1674582275,13.0-90.7
2023-02-22 13:31:29+00:00,1677072689,13.1-42.47
2023-04-05 06:57:33+00:00,1680677853,12.1-55.296
2023-04-12 08:05:14+00:00,1681286714,13.1-45.61
2023-04-17 18:09:24+00:00,1681754964,13.1-37.150
2023-04-19 15:34:38+00:00,1681918478,13.0-90.11
2023-04-26 11:42:55+00:00,1682509375,13.1-45.62
2023-04-28 20:39:00+00:00,1682714340,12.1-65.35
2023-04-30 08:54:31+00:00,1682844871,13.1-45.63
2023-05-12 04:49:56+00:00,1683866996,13.0-91.12
2023-05-12 07:33:58+00:00,1683876838,13.1-45.64
2023-05-15 10:23:44+00:00,1684146224,13.0-90.12
2023-06-03 07:35:50+00:00,1685777750,13.1-48.47
2023-07-07 15:32:56+00:00,1688743976,13.0-91.13
2023-07-07 16:17:07+00:00,1688746627,13.1-37.159
2023-07-07 16:29:27+00:00,1688747367,12.1-55.297
2023-07-10 18:36:31+00:00,1689014191,13.1-49.13
2023-07-28 00:25:01+00:00,1690503901,14.1-4.42
2023-08-30 07:03:54+00:00,1693379034,13.0-92.18
2023-09-15 06:40:36+00:00,1694760036,14.1-8.50
2023-09-21 05:25:24+00:00,1695273924,13.0-92.19
2023-09-21 06:17:01+00:00,1695277021,13.1-49.15
2023-09-21 17:12:48+00:00,1695316368,12.1-55.300
2023-09-27 12:27:52+00:00,1695817672,13.1-37.164
2023-10-18 07:27:04+00:00,1697614024,13.1-50.23
2023-11-22 18:19:39+00:00,1700677179,14.1-12.30
2023-12-08 19:10:40+00:00,1702062640,13.1-51.14
2023-12-14 10:12:36+00:00,1702548756,13.0-92.21
2023-12-15 07:26:58+00:00,1702625218,13.1-51.15
2023-12-15 09:18:34+00:00,1702631914,14.1-12.35
2023-12-18 07:59:52+00:00,1702886392,12.1-55.302
2024-01-05 04:15:53+00:00,1704428153,13.1-37.176
2024-02-08 05:34:51+00:00,1707370491,14.1-17.38
2024-02-29 17:31:08+00:00,1709227868,13.1-52.19
2024-04-18 21:13:30+00:00,1713474810,14.1-21.57
2024-05-01 05:48:44+00:00,1714542524,12.1-55.304
2024-05-13 16:45:28+00:00,1715618728,13.1-53.17
2024-05-14 12:55:51+00:00,1715691351,13.1-37.183
2024-06-08 07:28:50+00:00,1717831730,14.1-25.53
2024-07-04 10:41:15+00:00,1720089675,13.0-92.31
2024-07-04 14:32:40+00:00,1720103560,13.1-53.24
2024-07-04 16:31:28+00:00,1720110688,14.1-25.56
2024-07-17 17:53:35+00:00,1721238815,13.1-54.29
2024-10-11 10:23:04+00:00,1728642184,14.1-29.72
2024-10-22 01:37:14+00:00,1729561034,14.1-34.42
2024-10-24 13:43:49+00:00,1729777429,13.1-55.34
2024-11-07 16:17:10+00:00,1730996230,13.1-56.18
2024-12-16 17:20:08+00:00,1734369608,14.1-38.53
2025-01-25 10:12:49+00:00,1737799969,13.1-57.26
2025-06-07 13:53:15+00:00,1749304395,14.1-47.46
2025-06-10 10:53:47+00:00,1749552827,14.1-43.56
2025-06-10 20:52:27+00:00,1749588747,13.1-58.32
2025-06-10 14:02:25+00:00,1749564145,12.1-55.328
2025-06-18 13:04:11+00:00,1750251851,13.1-59.19
'''
dctStampToVersion = {}
for row in csv.DictReader(CITRIX_NETSCALER_VERSION_CSV.strip().splitlines()): dctStampToVersion[int(row['rdx_en_stamp'])] = row['version']
dctStampToVersion = dict(sorted(dctStampToVersion.items())) ## Sort it chronologically

def getIPsFromFile(sFile):
    lstLines = open(sFile,'r').read().splitlines()
    lstIPs = []
    for sLine in lstLines: ## Line can be an IP or a CIDR or a hostname
        for sIP in getIPs(sLine): lstIPs.append(sIP)
    return lstIPs

def getIPs(sCIDR): ## Could also be a single hostname
    import ipaddress
    try: lstIPs = [str(sTarget) for sTarget in list(ipaddress.ip_network(sCIDR, False).hosts())]
    except: ## Not an IP address but a hostname
        lstIPs = [sCIDR.replace('http://','').replace('https://','')]
    return lstIPs

def fingerPrint(listArgs): ## sTarget = either IP or FQDN
    (sTarget, boolVerbose, sProxy, boolVulns) = listArgs
    sURL = 'https://' + sTarget + '/vpn/js/rdx/core/lang/rdx_en.json.gz'
    try:
        if sProxy: oResponse = requests.get(sURL, verify=False, proxies={'https':sProxy}, stream=True)
        else: oResponse = requests.get(sURL, verify=False, stream=True)
    except:
        sURL = 'http://' + sTarget + '/vpn/js/rdx/core/lang/rdx_en.json.gz'
        try: 
            if sProxy: oResponse = requests.get(sURL, verify=False, proxies={'https':sProxy}, stream=True)
            else: oResponse = requests.get(sURL, verify=False, stream=True)
        except: 
            if boolVerbose: print(f'[-] {sTarget} is unresponsive')
            return
    oResponse.raw.decode_content = False
    bFileData = oResponse.raw.read()
    if bFileData.startswith(b'\x1f\x8b\x08\x08') and b'rdx_en.json' in bFileData:
        iStamp = int.from_bytes(bFileData[4:8], 'little')
        dtStamp = datetime.datetime.fromtimestamp(iStamp, datetime.timezone.utc)
        sVersion = dctStampToVersion.get(iStamp, None)
    else: return
    if sVersion: print(f'[+] https://{sTarget}: found Citrix Netscaler {sVersion} (Build date: {dtStamp})')
    else: 
        if dtStamp > (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=180)): 
            print(f'[!] https://{sTarget}: found a Citrix Netscaler with (recent) build date {dtStamp}')
        else: 
            print(f'[!] https://{sTarget}: found a Citrix Netscaler with build date {dtStamp}, which seems heavily outdated!')
    if (boolVulns): getVulns(sVersion.split('-')[0], sVersion.split('-')[-1], sTarget)
    return

### Vuln checking based on buildnumbers
def getVulns(sVersion, sBuild, sTarget): ## sVersion example: 12.1, sBuild example: 49.23
    print(f'[+] {sTarget}; scanning for critical vulnerabilities based on v{sVersion}-{sBuild}')
    ## CVE-2023-4966: Unauthenticated memory stealer, CitrixBleed (https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX579459)
    sVuln = f'  [!!] {sTarget} is vulnerable to CVE-2023-4966: CitrixBleed, unauthenticated memory leak when VPN, AAA or Proxy is enabled'
    
    if sVersion == '14.1':
        if int(sBuild.split('.')[0]) < 8 or (int(sBuild.split('.')[0]) == 8 and int(sBuild.split('.')[1]) < 50): print(sVuln)
    elif sVersion == '13.1':
        if int(sBuild.split('.')[0]) < 49 or (int(sBuild.split('.')[0]) == 49 and int(sBuild.split('.')[1]) < 15): print(sVuln)
    elif sVersion == '13.0':
        if int(sBuild.split('.')[0]) < 92 or (int(sBuild.split('.')[0]) == 92 and int(sBuild.split('.')[1]) < 19): print(sVuln)
    elif sVersion == '12.1':
        if int(sBuild.split('.')[0]) < 55 or (int(sBuild.split('.')[0]) == 55 and int(sBuild.split('.')[1]) < 300): print(sVuln)
    else: print(sVuln) ## Older always vulnerable
    
    ## CVE-2025-5777: Unauthenticated memory stealer, CitrixBleed 2 (https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420)
    sVuln = f'  [!!] {sTarget} is vulnerable to CVE-2025-5777: CitrixBleed 2, unauthenticated memory leak when VPN, AAA or Proxy is enabled'
    
    if sVersion == '14.1':
        if int(sBuild.split('.')[0]) < 43 or (int(sBuild.split('.')[0]) == 43 and int(sBuild.split('.')[1]) < 56): print(sVuln)
    elif sVersion == '13.1':
        if int(sBuild.split('.')[0]) < 58 or (int(sBuild.split('.')[0]) == 58 and int(sBuild.split('.')[1]) < 32): print(sVuln)
    elif sVersion == '13.0':
        if int(sBuild.split('.')[0]) < 37 or (int(sBuild.split('.')[0]) == 37 and int(sBuild.split('.')[1]) < 235): print(sVuln)
    elif sVersion == '12.1':
        if int(sBuild.split('.')[0]) < 55 or (int(sBuild.split('.')[0]) == 55 and int(sBuild.split('.')[1]) < 328): print(sVuln)
    else: print(sVuln) ## Older always vulnerable
    return
    
def main():
    sUsage = ('usage: %prog [options] SUBNET/ADDRESS/FILE\n'
              'This script performs enumeration of Citrix Netscaler systems on a given subnet, IP or file\n'
              'When provided with the --vulns parameter it spits out critical vulns based on the version.\n\n'
              'This script is 100% OPSEC safe')
    parser = optparse.OptionParser(usage = sUsage)
    parser.add_option('--threads', '-t', metavar='INT', dest='threads', default = 128, help='Amount of threads. Default 128')
    parser.add_option('--vulns', '-v', dest='vulns', action='store_true', help='Check for critical vulns.', default=False)
    parser.add_option('--proxy', '-p', metavar='STRING', dest='proxy', help='HTTP proxy (e.g. 127.0.0.1:8080), optional')
    parser.add_option('--verbose', dest='verbose', action='store_true', help='Verbosity. Default False', default=False)
    (options,lstArgs) = parser.parse_args()
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
    oPool.map(fingerPrint, zip(lstIPs, repeat(options.verbose), repeat(options.proxy), repeat(options.vulns)))

if __name__ == '__main__':
    main()
    exit()
