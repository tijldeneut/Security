#!/usr/bin/env python3
## Based on https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/vmware/esx_fingerprint.rb

import optparse, requests, os
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

iTimeout = 5

SM_TEMPLATE = b'''<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <env:Body>
      <RetrieveServiceContent xmlns="urn:vim25">
        <_this type="ServiceInstance">ServiceInstance</_this>
      </RetrieveServiceContent>
      </env:Body>
      </env:Envelope>'''

dicHeaders = {'User-Agent' : 'VMware VI Client', 'Content-Type': 'application/soap+xml; charset=utf-8', 'SOAPAction' : ''}

def getIPsFromFile(sFile):
    lstLines = open(sFile,'r').read().splitlines()
    lstIPs = []
    for sLine in lstLines: ## Line can be an IP or a CIDR
        for sIP in getIPs(sLine): lstIPs.append(sIP)
    return lstIPs

def getValue(sResponse, sTag = 'vendor'):
    try: return sResponse.split('<' + sTag + '>')[1].split('</' + sTag + '>')[0]
    except: pass
    return ''

def fingerPrint(listArgs):
    (sIP, boolVerbose, sProxy, boolVulns) = listArgs
    sURL = 'https://' + sIP + '/sdk'
    try:
        if sProxy: oResponse = requests.post(sURL, verify=False, data=SM_TEMPLATE, proxies={'https':sProxy}, headers = dicHeaders)
        else: oResponse = requests.post(sURL, verify=False, data=SM_TEMPLATE, headers = dicHeaders)
    except:
        if boolVerbose: print('[-] ' + sIP + ' is unresponsive')
        return
    if oResponse.status_code == 200:
        sResult = oResponse.text
        if boolVerbose: print(sResult)
        if not 'VMware' in getValue(sResult, 'vendor'):
            print('[-] ' + sIP + ': Not a VMware system')
        else:
            sName = getValue(sResult, 'name')
            sVersion = getValue(sResult, 'version')
            sBuild = getValue(sResult, 'build')
            sFull = getValue(sResult, 'fullName')
            if boolVulns: getVulns(sName, sVersion, sBuild, sIP, sFull)
            else: print('[+] ' + sIP + ': ' + sFull)

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
            if n&1:
                s = '1' + s
            else:
                s = '0' + s
            n >>= 1
        if d is not None:
            while len(s)<d:
                s = '0' + s
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

### Vuln checking based on buildnumbers
def getVulns(sName, sVersion, sBuild, sIP, sFull):
    ##  sName = VMware ESXi or VMware vCenter Server
    ##  sVersion = 7.0.1, 6.5.0 ...
    ##  sBuild = 14320388, 17167734 ...
    print('[+] ' + sIP + ': ' + sFull)
    ## CVE-2020-3992: ESXi RCE via TCP/427 (OpenSLP service) (https://www.vmware.com/security/advisories/VMSA-2020-0023.html)
    sVuln = '  [!!] ' + sIP + ' is vulnerable to CVE-2020-3992 and exploitable via CVE-2021-21974: RCE via OpenSLP'
    if 'ESXi' in sName:
        if (int(sVersion.split('.')[0]) < 6) or (int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 0):
            print(sVuln)
        elif int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 5:
            if int(sBuild) < 16901156: print(sVuln)
        elif int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 7:
            if int(sBuild) < 16773714: print(sVuln)
        elif int(sVersion.split('.')[0]) == 7:
            if int(sBuild) < 16850804: print(sVuln)
    ## CVE-2020-3952: vCenter Authentication Bypass via vmdir (TCP/389) (https://www.vmware.com/security/advisories/VMSA-2020-0006.html)
    sVuln = '  [!!] ' + sIP + ' may be vulnerable to CVE-2020-3952: Authentication Bypass in case the system was upgraded in the past'
    if 'vCenter' in sName:
        if int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 7:
            if int(sBuild) < 15976714: print(sVuln)
    ## CVE-2015-2342: vCenter RCE via TCP/9875 (jConsole) (https://www.vmware.com/be/security/advisories/VMSA-2015-0007.html)
    sVuln = '  [!!] ' + sIP + ' is vulnerable to CVE-2015-2342: Unauthenticated RCE via jConsole TCP/9875'
    if 'vCenter' in sName:
        if int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 0:
            if int(sBuild) < 3018524: print(sVuln)
        if int(sVersion.split('.')[0]) == 5 and int(sVersion.split('.')[1]) == 5:
            if int(sBuild) < 3000241: print(sVuln)
        if int(sVersion.split('.')[0]) == 5 and int(sVersion.split('.')[1]) == 1:
            if int(sBuild) < 3070521: print(sVuln)
        if int(sVersion.split('.')[0]) == 5 and int(sVersion.split('.')[1]) == 0:
            if int(sBuild) < 3073236: print(sVuln)
    ## CVE-2019-...: vCenter LFI via /eam/vib?id=/etc/issue or /eam/vib?id=C:\ProgramData\VMware\vCenterServer\cfg\vmware-vpx\vcdb.properties
    ##  https://cyberwarzone.com/unauthenticated-arbitrary-file-read-vulnerability-in-vmware-vcenter/
    sVuln = '  [!!] ' + sIP + ' is vulnerable to Unauthenticated Arbitrary File Read'
    if 'vCenter' in sName:
        if int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 5:
            if int(sBuild) < 5973321: print(sVuln)
        if int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 0: print(sVuln)
    ## CVE-2021-21972: vCenter Arbitrary File Upload, resulting in RCE in every version (https://www.vmware.com/security/advisories/VMSA-2021-0002.html)
    sVuln = '  [!!] ' + sIP + ' is vulnerable to CVE-2021-21972: Unauthenticated Arbitrary File Upload and RCE'
    if 'vCenter' in sName:
        if int(sVersion.split('.')[0]) == 7:
            if int(sBuild) < 17327517: print(sVuln)
        if int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 7:
            if int(sBuild) < 17137327: print(sVuln) # Strictly this should be 17138064, but a bug makes it show up as 17137327
        if int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 5:
            if int(sBuild) < 17590285: print(sVuln)
        #if int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 0: print(sVuln)
    ## CVE-2021-21985: RCE in the always enabled vCenter VSAN plugin TCP/443 (https://www.vmware.com/security/advisories/VMSA-2021-0010.html)
    sVuln = '  [!!] ' + sIP + ' is vulnerable to CVE-2021-21985: Unauthenticated RCE in the default enabled VSAN plugin'
    if 'vCenter' in sName:
        if int(sVersion.split('.')[0]) == 7:
            if int(sBuild) < 17958471: print(sVuln)
        if int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 7:
            if int(sBuild) < 18010531: print(sVuln)
        if int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 5:
            if int(sBuild) < 17994927: print(sVuln)
    ## CVE-2021-22005: File Upload and RCE in the default enabled CEIP on vCenter 6.7 & 7.0 (https://www.vmware.com/security/advisories/VMSA-2021-0020.html)
    sVuln = '  [!!] ' + sIP + ' is vulnerable to CVE-2021-22005: Unauthenticated File Upload and RCE on the default enabled CEIP'
    if 'vCenter' in sName:
        if int(sVersion.split('.')[0]) == 7:
            if int(sBuild) < 18356314: print(sVuln)
        if int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 7:
            if int(sBuild) < 18485166: print(sVuln)
    ## CVE-2021-44228: Log4J RCE as limited user on v6.5, v6.7 and v7 (Win+VCSA) (https://www.vmware.com/security/advisories/VMSA-2021-0028.html)
    sVuln = '  [!!] ' + sIP + ' is vulnerable to CVE-2021-44228: RCE as root via Log4J on v6.5, v6.7 and v7.0 on both Windows/VCSA'
    if 'vCenter' in sName:
        if int(sVersion.split('.')[0]) == 7:
            if int(sBuild) < 19234570: print(sVuln)
        if int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 7:
            if int(sBuild) < 19300125: print(sVuln)
        if int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 5:
            if int(sBuild) < 19261680: print(sVuln)
    ## CVE-2023-34048: DCERPC out-of-bounds used in Malware (https://www.vmware.com/security/advisories/VMSA-2023-0023.html) (https://blog.sonicwall.com/en-us/2023/12/vmware-vcenter-dcerpc-dealloc-pointer-manipulation/)
    sVuln = '  [!!] ' + sIP + ' is vulnerable to CVE-2023-34048: RCE via the DCE RPC protocol on v4, v5, v6, v7 and v8'
    if 'vCenter' in sName:
        if int(sVersion.split('.')[0]) == 8 and int(sVersion.split('.')[1]) == 0 and int(sVersion.split('.')[2]) == 2:
            if int(sBuild) < 22385739: print(sVuln)
        elif int(sVersion.split('.')[0]) == 8 and int(sVersion.split('.')[1]) == 0 and int(sVersion.split('.')[2]) == 1:
            if int(sBuild) < 22368047: print(sVuln)
        elif int(sVersion.split('.')[0]) == 7:
            if int(sBuild) < 22357613: print(sVuln)
        elif int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 7:
            if int(sBuild) < 22509723: print(sVuln)
        elif int(sVersion.split('.')[0]) == 6 and int(sVersion.split('.')[1]) == 5:
            if int(sBuild) < 22499743: print(sVuln)
        elif int(sVersion.split('.')[0]) <= 5: print(sVuln) ## 6.0 or lower is always vulnerable
    ## CVE-2024-22274: Authenticated RCE on vCenter (https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24308) (https://github.com/mbadanoiu/CVE-2024-22274)
    ##  Requirements too high, not critical
    ## CVE-2024-38812: Unauthenticated RCE on vCenter via DCERPC (https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24968)
    ##  Found as part of Matrix Cup contest and Broadcom confirmed exploitation in the wild occurs
    sVuln = '  [!!] ' + sIP + ' is vulnerable to CVE-2024-38812: Unauthenticated RCE via the DCE RPC protocol on v7 and v8'
    if 'vCenter' in sName:
        if int(sVersion.split('.')[0]) == 8 and int(sVersion.split('.')[1]) == 0 and int(sVersion.split('.')[2]) == 3:
            if int(sBuild) < 24322831: print(sVuln)
        elif int(sVersion.split('.')[0]) == 8 and int(sVersion.split('.')[1]) == 0 and int(sVersion.split('.')[2]) == 2:
            if int(sBuild) < 24321653: print(sVuln)
        elif int(sVersion.split('.')[0]) == 7:
            if int(sBuild) < 24322018: print(sVuln)
    return
    
def main():
    sUsage = ('usage: %prog [options] SUBNET/ADDRESS/FILE\n'
              'This script performs enumeration of ESXi & vCenter systems on a given subnet, IP or file\n'
              'When provided with the --vulns parameter it spits out critical vulns based on the buildnr.\n\n'
              'This script is 100% OPSEC safe!')
    parser = optparse.OptionParser(usage = sUsage)
    parser.add_option('--threads', '-t', metavar='INT', dest='threads', default = 128, help='Amount of threads. Default 128')
    parser.add_option('--vulns', '-v', dest='vulns', action="store_true", help='Check for common vulns.', default=False)
    parser.add_option('--proxy', '-p', metavar='STRING', dest='proxy', help='HTTP proxy (e.g. 127.0.0.1:8080), optional')
    parser.add_option('--verbose', dest='verbose', action="store_true", help='Verbosity. Default False', default=False)
    (options,lstArgs) = parser.parse_args()
    if not lstArgs or not len(lstArgs) == 1:
        sCIDR = input('[?] Please enter the subnet or IP to scan [192.168.50.0/24] : ')
        if sCIDR == '': sCIDR = '192.168.50.0/24'
    else:
        if os.path.isfile(lstArgs[0]):
            print('[+] Parsing file {} for IP addresses/networks.'.format(lstArgs[0]))
            lstIPs = getIPsFromFile(lstArgs[0])
        else:
            sCIDR = lstArgs[0]
            lstIPs = getIPs(sCIDR)
    
    oPool = ThreadPool(int(options.threads))
    print('[!] Scanning ' + str(len(lstIPs)) + ' addresses using up to ' + str(options.threads) + ' threads.')
    oPool.map(fingerPrint, zip(lstIPs, repeat(options.verbose), repeat(options.proxy), repeat(options.vulns)))

if __name__ == "__main__":
    main()
