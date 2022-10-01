#! /usr/bin/env python3
# -*- coding: utf-8 -*- 
r''' 
    	Copyright 2022 Photubias(c)

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

        Native version check? Open Management Shell and run:
         PS> Get-Command Exsetup.exe | ForEach {$_.FileVersionInfo}
        
        File name Exchange-fingerprinter.py
        written by tijl[dot]deneut[at]howest[dot]be for www.ic4.be

        This script tries to detect the MS Exchange OWA / ECP version.
        And also pinpoints a couple of vulnerabilities (Example: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855)

        Exchange Versions   Full builds (https://docs.microsoft.com/en-us/Exchange/new-features/build-numbers-and-release-dates)
        2019 == 15.2.x.y
        2016 == 15.1.x.y
        2013 == 15.0.x.y
        2010 == 14.x.y.z     Rollup32 (2021-03-02): 14.3.513.0 
        2007 == 8.x.y.z      Rollup23 (2017-03-21): 8.3.517.0
        2003 == 6.5.x        Post-SP2: (2008-08): 6.5.7654.4
        2000 == 6.0.x        Post-SP3: (2008-08): 6.0.6620.7
        Everything older is just version nr == Exchange version
'''
import urllib, argparse, ssl, http.cookiejar
lstPatchedProxyLogon = {
    '2019':{'221.18':'RTM','330.11':'CU1','397.11':'CU2','464.15':'CU3','529.13':'CU4','595.8':'CU5','659.12':'CU6','721.13':'CU7','792.10':'CU8'},
    '2016':{'1415.10':'CU8','1466.16':'CU9','1531.12':'CU10','1591.18':'CU11','1713.10':'CU12','1779.8':'CU13','1847.12':'CU14','1913.12':'CU15','1979.8':'CU16','2044.13':'CU17','2106.13':'CU18','2176.9':'CU19'},
    '2013':{'1395.12':'CU21','1473.6':'CU22','1497.12':'CU23'}
    }
lstPatchedProxyShell = {
    '2019':{'792.13':'CU8','858.10':'CU9'},
    '2016':{'2176.12':'CU19','2242.8':'CU20'},
    '2013':{'1497.15':'CU23'}
}
lstPatchedProxyNotShell = {
    '2019':{'986.30':'CU11','1118.13':'CU12'},
    '2016':{'2375.32':'CU22','2507.13':'CU23'},
    '2013':{'1497.41':'CU23'}
}

def isVulnerable(version):
    def isItVuln(sMajor, sMinor, sBuild, lstVerify): ## E.g. ('2016', '2106', '12')
        iHighestListedMinor = 0
        for x in lstVerify[sMajor]:
            if int(x.split('.')[0]) > iHighestListedMinor: iHighestListedMinor = int(x.split('.')[0])
            if x.split('.')[0] == str(sMinor):
                if int(sBuild) < int(x.split('.')[1]): return (lstVerify[sMajor][x],'vuln') ## CU in list but older version: vulnerable
                else: return (lstVerify[sMajor][x],'patched') ## CU in list but not vulnerable: patched
        ## CU not in list: patched if larger than highest minor
        if int(sMinor) > iHighestListedMinor: return (None, 'patched') ## Technically not patched but the CU was never vulnerable
        return (None, 'vuln')
    buildnr = version.split('.')
    try: int(buildnr[2])
    except:
        print('[!] Too old to confirm any vulnerabilities')
        return False
    if(len(buildnr) < 3): buildnr.append(0)
    if(len(buildnr) < 4): 
        buildnr.append(0)
        print('[!] Warning! Did not find exact build number (which includes a 4th digit), unstable vulnerability checker')
    
    if buildnr[0] == '15': ## 2013, 2016 or 2019
        if buildnr[1] == '2':
            print('[+] Exchange Server 2019 detected')
            ## CVE-2022-41082 (ProxyNotShell)
            sResult = isItVuln('2019', buildnr[2], buildnr[3], lstPatchedProxyNotShell)
            if sResult[0] and sResult[1] == 'vuln': print('[!] Unpatched {}: vulnerable to CVE-2022-41082/41040 (Authenticated RCE, also called ProxyNotShell)'.format(sResult[0]))
            elif not sResult[0] and sResult[1] == 'vuln': print('[!] Vulnerable to CVE-2022-41082/41040 (Authenticated RCE, also called ProxyNotShell)')
            ## CVE-2021-33766 (ProxyShell)
            sResult = isItVuln('2019', buildnr[2], buildnr[3], lstPatchedProxyShell)
            if sResult[0] and sResult[1] == 'vuln': print('[!] Unpatched {}: vulnerable to CVE-2021-33766/34473/34523/31207 (Unauthenticated RCE, also called ProxyShell)'.format(sResult[0]))
            elif not sResult[0] and sResult[1] == 'vuln': print('[!] Vulnerable to CVE-2021-33766/34473/34523/31207 (Unauthenticated RCE, also called ProxyShell)')
            ## CVE-2021-26855 (ProxyLogon)
            sResult = isItVuln('2019', buildnr[2], buildnr[3], lstPatchedProxyLogon)
            if sResult[0] and sResult[1] == 'vuln': print('[!] Unpatched {}: vulnerable to CVE-2021-26855/27065 (Unauthenticated RCE, also called ProxyLogon)'.format(sResult[0]))
            elif not sResult[0] and sResult[1] == 'vuln': print('[!] Vulnerable to CVE-2021-26855/27065 (Unauthenticated RCE, also called ProxyLogon)')
            ## CVE-2021-28480
            if int(buildnr[2]) <= 858:
                print('[?] Possible unauthenticated RCE: CVE-2021-28480,1,2,3.')
                print('    Verify with PowerShell command \'Get-Command Exsetup.exe | ForEach {$_.FileVersionInfo}\'')
                print('    15.2.585.9 or higher is patched')
            elif int(buildnr[2]) < 858:
                print('[+] Confirmed unauthenticated RCE: CVE-2021-28480,1,2,3.')
            ## CVE-2020-0688
            if int(buildnr[2]) == 529:
                if 0 < int(buildnr[3]) < 8: 
                    print('[+] Unpatched CU4: vulnerable to CVE-2020-0688 (authenticated RCE)')
                    return True
                else: 
                    print('[?] Possible authenticated RCE for this CU4: CVE-2020-0688')
                    print('    Verify with PowerShell command \'Get-Command Exsetup.exe | ForEach {$_.FileVersionInfo}\'')
                    print('    15.2.529.8 or higher is patched')
                    return False
            elif int(buildnr[2]) == 464:
                if 0 < int(buildnr[3]) < 11: 
                    print('[+] Unpatched CU3: vulnerable to CVE-2020-0688 (authenticated RCE)')
                    return True
                else: 
                    print('[?] Possible authenticated RCE for this CU3: CVE-2020-0688')
                    print('    Verify with PowerShell command \'Get-Command Exsetup.exe | ForEach {$_.FileVersionInfo}\'')
                    print('    15.2.464.11 or higher is patched')
                    return False
            else:
                print('[+] Vulnerable to CVE-2020-0688 (authenticated RCE)')
                return True
        elif buildnr[1] == '1':
            print('[+] Exchange Server 2016 detected')
           ## CVE-2022-41082 (ProxyNotShell)
            sResult = isItVuln('2016', buildnr[2], buildnr[3], lstPatchedProxyNotShell)
            if sResult[0] and sResult[1] == 'vuln': print('[!] Unpatched {}: vulnerable to CVE-2022-41082/41040 (Authenticated RCE, also called ProxyNotShell)'.format(sResult[0]))
            elif not sResult[0] and sResult[1] == 'vuln': print('[!] Vulnerable to CVE-2022-41082/41040 (Authenticated RCE, also called ProxyNotShell)')
            #elif sResult[0] and sResult[1] == 'patched': print('[!] Congrats, I found a patched {}'.format(sResult[0]))
            ## CVE-2021-33766 (ProxyShell)
            sResult = isItVuln('2016', buildnr[2], buildnr[3], lstPatchedProxyShell)
            if sResult[0] and sResult[1] == 'vuln': print('[!] Unpatched {}: vulnerable to CVE-2021-33766/34473/34523/31207 (Unauthenticated RCE, also called ProxyShell)'.format(sResult[0]))
            elif not sResult[0] and sResult[1] == 'vuln': print('[!] Vulnerable to CVE-2021-33766/34473/34523/31207 (Unauthenticated RCE, also called ProxyShell)')
            ## CVE-2021-26855 (ProxyLogon)
            sResult = isItVuln('2016', buildnr[2], buildnr[3], lstPatchedProxyLogon)
            if sResult[0] and sResult[1] == 'vuln': print('[!] Unpatched {}: vulnerable to CVE-2021-26855/27065 (Unauthenticated RCE, also called ProxyLogon)'.format(sResult[0]))
            elif not sResult[0] and sResult[1] == 'vuln': print('[!] Vulnerable to CVE-2021-26855/27065 (Unauthenticated RCE, also called ProxyLogon)')
            ## CVE-2021-28480
            if int(buildnr[2]) <= 2242:
                print('[?] Possible unauthenticated RCE: CVE-2021-28480,1,2,3')
                print('    Verify with PowerShell command \'Get-Command Exsetup.exe | ForEach {$_.FileVersionInfo}\'')
                print('    15.1.2242.5 or higher is patched')
            elif int(buildnr[2]) < 2242:
                print('[-] Confirmed unauthenticated RCE: CVE-2021-28480,1,2,3')
            ## CVE-2020-0688
            if int(buildnr[2]) > 1913: 
                #print('[-] Not vulnerable to CVE-2020-0688; > CU16 and up')
                return False
            elif int(buildnr[2]) == 1913: 
                if 0 < int(buildnr[3]) < 7:
                    print('[+] Unpatched CU15: vulnerable to CVE-2020-0688 (authenticated RCE)')
                    return True
                else: 
                    print('[?] Possible authenticated RCE for this CU15: CVE-2020-0688')
                    print('    Verify with PowerShell command \'Get-Command Exsetup.exe | ForEach {$_.FileVersionInfo}\'')
                    print('    15.1.1913.7 or higher is patched')
                    return False
            elif int(buildnr[2]) == 1847: 
                if 0 < int(buildnr[3]) < 7:
                    print('[+] Unpatched CU14: vulnerable to CVE-2020-0688 (authenticated RCE)')
                    return True
                else: 
                    print('[?] Possible authenticated RCE for this CU14: CVE-2020-0688')
                    print('    Verify with PowerShell command \'Get-Command Exsetup.exe | ForEach {$_.FileVersionInfo}\'')
                    print('    15.1.1847.7 or higher is patched')
                    return False
            else:
                print('[+] Vulnerable to CVE-2020-0688 (authenticated RCE)')
                return True
        elif buildnr[1] == '0':
            print('[+] Exchange Server 2013 detected')
             ## CVE-2022-41082 (ProxyNotShell)
            sResult = isItVuln('2013', buildnr[2], buildnr[3], lstPatchedProxyNotShell)
            if sResult[0] and sResult[1] == 'vuln': print('[!] Unpatched {}: vulnerable to CVE-2022-41082/41040 (Authenticated RCE, also called ProxyNotShell)'.format(sResult[0]))
            elif not sResult[0] and sResult[1] == 'vuln': print('[!] Vulnerable to CVE-2022-41082/41040 (Authenticated RCE, also called ProxyNotShell)')
            ## CVE-2021-33766 (ProxyShell)
            sResult = isItVuln('2013', buildnr[2], buildnr[3], lstPatchedProxyShell)
            if sResult[0] and sResult[1] == 'vuln': print('[!] Unpatched {}: vulnerable to CVE-2021-33766/34473/34523/31207 (Unauthenticated RCE, also called ProxyShell)'.format(sResult[0]))
            elif not sResult[0] and sResult[1] == 'vuln': print('[!] Vulnerable to CVE-2021-33766/34473/34523/31207 (Unauthenticated RCE, also called ProxyShell)')
            ## CVE-2021-26855 (ProxyLogon)
            sResult = isItVuln('2013', buildnr[2], buildnr[3], lstPatchedProxyLogon)
            if sResult[0] and sResult[1] == 'vuln': print('[!] Unpatched {}: vulnerable to CVE-2021-26855/27065 (Unauthenticated RCE, also called ProxyLogon)'.format(sResult[0]))
            elif not sResult[0] and sResult[1] == 'vuln': print('[!] Vulnerable to CVE-2021-26855/27065 (Unauthenticated RCE, also called ProxyLogon)')
            ## CVE-2021-28480
            if int(buildnr[2]) <= 1497:
                print('[?] Possible unauthenticated RCE: CVE-2021-28480,1,2,3')
                print('    Verify with PowerShell command \'Get-Command Exsetup.exe | ForEach {$_.FileVersionInfo}\'')
                print('    15.0.1497.15 or higher is patched')
            elif int(buildnr[2]) < 1497:
                print('[-] Confirmed unauthenticated RCE: CVE-2021-28480,1,2,3.')
            ## CVE-2020-0688
            if int(buildnr[2]) > 1497: 
                #print('[-]  Not vulnerable to CVE-2020-0688; > CU24 and up')
                return False
            elif int(buildnr[2]) == 1497: 
                if 0 < int(buildnr[3]) < 6:
                    print('[+] Unpatched CU23: vulnerable to CVE-2020-0688 (authenticated RCE)')
                    return True
                else: 
                    print('[?] Possible authenticated RCE for this CU23: CVE-2020-0688')
                    print('    Verify with PowerShell command \'Get-Command Exsetup.exe | ForEach {$_.FileVersionInfo}\'')
                    print('    15.0.1497.6 or higher is patched')
                    return False
            else:
                print('[+] Vulnerable to CVE-2020-0688 (authenticated RCE)')
                return True
    elif buildnr[0] == '14': ## 2010, 2021-28480 not an option here
        print('[+] Exchange Server 2010 detected')
        ## CVE-2020-0688
        if int(buildnr[2]) >= 496: 
            #print('[-] Not vulnerable to CVE-2020-0688; > Rollup30 and up')
            return False
        else:
            print('[+] Vulnerable to CVE-2020-0688 (authenticated RCE)')
            return True
    elif buildnr[0] == '8':
        print('[+] Exchange Server 2007 detected, no recent vulns, but please upgrade')
        return True
    elif buildnr[0] == '6' and buildnr[1] == '5':
        print('[+] Exchange Server 2003 detected, no recent vulns, but please upgrade')
        return True
    elif buildnr[0] == '6' and buildnr[1] == '0':
        print('[+] Exchange Server 2000 detected, no recent vulns, but please upgrade')
        return True
    print('[+] Exchange Server '+version +' detected, no recent vulns, but please upgrade')
    return True

def tryGetHeader(sTarget):
    class NoRedirection(urllib.request.HTTPErrorProcessor):
        def http_response(self, request, response): return response
        https_response = http_response
    oOpener = urllib.request.build_opener(NoRedirection)
    return oOpener.open(sTarget).headers['X-OWA-Version']

def getVersion(sTarget, oOpener):
    if not sTarget[-1:] == '/': sTarget += '/'
    if not sTarget[:4].lower() == 'http': sTarget = 'https://' + sTarget
    ## Calling (modern) OWA systems without redirect sets a header with the version
    sVersion = tryGetHeader(sTarget)
    if sVersion: return sVersion

    try:
        oResponse = oOpener.open(sTarget + 'owa/auth.owa')
        sResult = oResponse.read().decode('latin_1')
    except:
        try:
            oResponse = oOpener.open(sTarget + '/owa/auth/logon.aspx')
            sResult = oResponse.read().decode('latin_1')
        except:
            print('[!] Error, ' + sTarget + ' not reachable')
    
    ## Verify OWA Version
    sVersion = 'Unknown'
    try: sVersion = sResult.split('owa/auth/')[1].split('/')[0]
    except:
        try: sVersion = sResult.split('stylesheet')[0].split('href="')[1].split('/')[2]
        except: sVersion = 'Unknown'
    return sVersion
   
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', required=False, help='Target IP or hostname (e.g. https://owa.contoso.com)', default='')
    args = parser.parse_args()
    if not args.target: args.target = input('[?] Please enter the IP or hostname e.g. https://owa.contoso.com: ')
    
    ssl._create_default_https_context = ssl._create_unverified_context
    oCookjar = http.cookiejar.CookieJar()
    sProxy = '127.0.0.1:8080'
    oOpener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': '127.0.0.1:8080'}), urllib.request.HTTPCookieProcessor(oCookjar))
    #oOpener.set_proxy(sProxy, 'http')

    sVersion = getVersion(args.target, oOpener)
    if sVersion == 'Unknown':
        print('[-] Unknown version or this is not Exchange, skipping vulnerability check')
    else:
        print('[+] Detected OWA version number ' + sVersion)
        isVulnerable(sVersion)
        
if __name__ == "__main__":
	main()
