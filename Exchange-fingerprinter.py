#! /usr/bin/env python3
# -*- coding: utf-8 -*- 
r''' 
    	Copyright 2021 Photubias(c)

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
        And also pinpoints a couple of vulnerabilities

        ## INFO:
        #  CVE-2020-0688 (Authenticated RCE),
        #   fixed in Exchange 2019 15.2.529.8 & 15.2.464.11
        #   fixed in Exchange 2016 15.1.1913.7 & 15.1.1847.7
        #   fixed in Exchange 2013 15.0.1497.6
        #   fixed in Exchange 2010 14.3.496.0
        #   Exchange 2007 (8.x) Not Vulnerable
        #   Exchange 2003 (6.5) Not Vulnerable
        #   Exchange 2000 (6.0) Not Vulnerable
        #   Everything older is just version == Exchange version (Not Vulnerable)

        # CVE-2021-28480,1,2,3 (Unauthenticated RCE's)
        #   fixed in Exchange 2019 15.2.585.9 & 15.2.792.13
        #   fixed in Exchange 2016 15.1.2242.5 & 15.1.2176.12
        #   fixed in Exchange 2013 15.0.1497.15
        #   Everything older not vulnerable

        Exchange Versions   Full builds (https://docs.microsoft.com/en-us/Exchange/new-features/build-numbers-and-release-dates)
        2019 == 15.2.x.y     CU4 (2019-12-17): 15.2.529.5 (CU3 = 15.2.464.5) (fixed in 529.8 and 464.11)
        2016 == 15.1.x.y     CU15 (2019-12-17): 15.1.1913.5 (CU14 = 15.1.1847.3) (fixed in 1913.7 and 1847.7)
        2013 == 15.0.x.y     CU23 (2019-06-18): 15.0.1497.2 (fixed in 1497.6)
        2010 == 14.x.y.z     Rollup30 (2020-02-11): 14.3.496.0 
        2007 == 8.x.y.z      Rollup23 (2017-03-21): 8.3.517.0
        2003 == 6.5.x
        2000 == 6.0.x
        Everything older is just version nr == Exchange version
'''
import urllib, argparse, sys, ssl, http.cookiejar

def isVulnerable(version):
    buildnr = version.split('.')
    try:
        int(buildnr[2])
    except:
        print('[!] Too old to confirm any vulnerabilities')
        return False
    if(len(buildnr) < 3): buildnr.append(0)
    if(len(buildnr) < 4): buildnr.append(0)
    if buildnr[0] == '15': ## 2013, 2016 or 2019
        if buildnr[1] == '2':
            print('[!] Exchange Server 2019 detected')
            ## CVE-2021-28480
            if int(buildnr[2]) <= 858:
                print('[?] Possible unauthenticated RCE: CVE-2021-28480,1,2,3.')
                print('    Verify with PowerShell command \'Get-Command Exsetup.exe | ForEach {$_.FileVersionInfo}\'')
                print('    15.2.585.9 or higher is patched')
            elif int(buildnr[2]) < 858:
                print('[+] Confirmed unauthenticated RCE: CVE-2021-28480,1,2,3.')
            ## CVE-2020-0688
            if int(buildnr[2]) > 529: 
                #print('[-] Not vulnerable to CVE-2020-0688; > CU5 and up')
                return False
            elif int(buildnr[2]) == 529:
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
            print('[!] Exchange Server 2016 detected')
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
            print('[!] Exchange Server 2013 detected')
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
        print('[!] Exchange Server 2010 detected')
        ## CVE-2020-0688
        if int(buildnr[2]) >= 496: 
            #print('[-] Not vulnerable to CVE-2020-0688; > Rollup30 and up')
            return False
        else:
            print('[+] Vulnerable to CVE-2020-0688 (authenticated RCE)')
            return True
    elif buildnr[0] == '8':
        print('[!] Exchange Server 2007 detected, no recent vulns, but please upgrade')
        return True
    elif buildnr[0] == '6' and buildnr[1] == '5':
        print('[+] Exchange Server 2003 detected, no recent vulns, but please upgrade')
        return True
    elif buildnr[0] == '6' and buildnr[1] == '0':
        print('[+] Exchange Server 2000 detected, no recent vulns, but please upgrade')
        return True
    print('[+] Exchange Server '+version +' detected, no recent vulns, but please upgrade')
    return True

def getVersion(sTarget, oOpener):
    if not sTarget[-1:] == '/': sTarget += '/'
    if not sTarget[:4].lower() == 'http': sTarget = 'https://' + sTarget
    try:
        sResult = oOpener.open(sTarget + 'owa/auth.owa').read().decode('latin_1')
    except:
        try:
            sResult = oOpener.open(sTarget + '/owa/auth/logon.aspx').read().decode('latin_1')
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
    oOpener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(oCookjar))

    sVersion = getVersion(args.target, oOpener)
    if sVersion == 'Unknown':
        print('[-] Unknown version or this is not Exchange, skipping vulnerability check')
    else:
        print('[+] Detected OWA version number ' + sVersion)
        isVulnerable(sVersion)
        
if __name__ == "__main__":
	main()
