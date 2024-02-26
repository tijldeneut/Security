#! /usr/bin/env python3
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
        
        File name SSH-fingerprinter.py
        written by Tijl Deneut

'''
import argparse, sys, socket, time
try: import paramiko
except: exit('[-] Error: Paramiko required: python3 -m pip install paramiko')

iTimeout = 2 ## seconds

def getBanner(arrArgs):
    #sIP, iPort, boolVerbose
    sIP = arrArgs[0]; iPort = arrArgs[1]; boolVerbose = arrArgs[2]
    sBanner = ''
    try:
        oSock = socket.create_connection((sIP, iPort), timeout=iTimeout)
        bBanner = oSock.recv(1024)
        oSock.close()
        try: 
            sBanner = bBanner.split(b"\n")[0].decode(errors='ignore')
            print('[+] Connection {}:{} has banner {}'.format(sIP, iPort, sBanner))
        except: pass
    except:
        if boolVerbose: print('[-] Connection {}:{} timed out'.format(sIP, iPort))
    return sBanner

def getPrompt(oShell):
    def flush(oShell):
        while oShell.recv_ready(): oShell.recv(1024)
    flush(oShell)  # flush everything from before
    #oShell.sendall('\n') ## sometimes needed, but not on fortigates

    time.sleep(.3)
    sPrompt = str(oShell.recv(1024), encoding='utf-8').strip()
    flush(oShell)  # flush everything after (just in case)
    return sPrompt

def openConnection(sIP,iPort,sUsername,sPassword, boolVerbose=False):
    oSSH = paramiko.SSHClient()
    oSSH.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ## Create connection
    try: oSSH.connect(hostname=sIP, port=iPort, username=sUsername, password=sPassword)
    except:
        print('[-] Error: Creds for {} are not working (username: {}, port: {})'.format(sIP, sUsername, iPort)) 
        exit(0)
    ## Getting the prompt (hostname)
    sPrompt = getPrompt(oSSH.invoke_shell())
    if boolVerbose: print('Prompt: {}'.format(sPrompt))
    
    ## Verify filesystem access
    oStdin, oStdout, oStderr = oSSH.exec_command('fnsysctl ls -al /')
    if oStderr.read() != b'': 
        print('[-] User {} does not have the correct privileges on device {}'.format(sUsername, sIP))
        exit(0)
    
    return oSSH, sPrompt

def getFilelist(oSSH, sPrompt, sPath):
    lstFiles = []
    oStdin, oStdout, oStderr = oSSH.exec_command('fnsysctl ls -al {}'.format(sPath))
    for sLine in oStdout.readlines(): lstFiles.append(sLine.replace(sPrompt,'').replace('\n','').strip())
    return lstFiles

def checkIOCDATA2(oSSH, sPrompt):
    lstFiles = getFilelist(oSSH, sPrompt, '/data2/')
    boolIOC = False
    for sLine in lstFiles:
        sFile = sLine.split(' ')[-1]
        if sFile == '.' or sFile == '..': continue
        if len(sFile) == 0: continue
        if sFile[0] == '.' and sLine[0] == 'd': 
            print('[+] Found hidden folder in /data2/: {}'.format(sFile))
            print('     Verifying the presence of IOC\'s:')
            lstSubFiles = getFilelist(oSSH, sPrompt, '/data2/{}'.format(sFile))
            for sSubline in lstSubFiles:
                if 'authd' in sSubline or 'httpsd' in sSubline or 'newcli' in sSubline or 'preload.so' in sSubline or 'sh' in sSubline:
                    boolIOC = True
                    sSubfile = sSubline.split(' ')[-1]
                    print('[!] IOC !! /data2/{}/{}'.format(sFile, sSubfile))
            if not boolIOC:
                print('[+] No confirmed IOC\'s found in this folder, but printing contents anyway:')
                for sSubline in lstSubFiles: print(sSubline)
    return boolIOC

def checkIOCFile(oSSH, sPrompt, sFilepath):
    oStdin, oStdout, oStderr = oSSH.exec_command('fnsysctl ls -al {}'.format(sFilepath))
    sOutput = oStdout.read().decode(errors='ignore').replace(sPrompt,'').replace('\n','').strip()
    if 'No such file or directory' in oStderr.read().decode(errors='ignore'): return False
    print('[+] Warning: IOC {} has been found, full output:'.format(sFilepath))
    print('    {}'.format(sOutput))
    return True

def checkIOCTimes(oSSH, sPrompt):
    oStdin, oStdout, oStderr = oSSH.exec_command('fnsysctl ls -aAl /bin/smartctl /bin/smbcd')
    sTime1 = sTime2 = ''
    for sLine in oStdout.readlines():
        sLine = sLine.replace(sPrompt,'').replace('\n','').strip()
        sFile = sLine.split(' ')[-1]
        if len(sLine) == 0: continue
        sTimestamp = sLine.split('    ')[4].strip()
        if sTime1 == '': sTime1 == sTimestamp
        else: sTime2 == sTimestamp
    if sTime1 != sTime2:
        print('[!] IOC found: file /bin/smartctl has different timestamp than /bin/smbcd.\n     Check folder /bin.')
        #for sLine in getFilelist(oSSH, sPrompt, '/bin/'): print(sLine)
        return True
    else: return False

def main():
    boolVerbose = False
    ## Banner
    print(r'''
    [*****************************************************************************]
                         --- SSH COATHANGER IOC CHECKER ---
    This script will try to connect to a running FortiGate device via SSH 
                         and detect some distinct IOCs.
    ______________________/-> Created By Tijl Deneut(c) <-\_______________________
    [*****************************************************************************]
    ''')
    ## Defaults and parsing arguments
    oParser = argparse.ArgumentParser()
    oParser.add_argument('-t', '--target', help='TARGET mode, provide IP address', default='')
    oParser.add_argument('-p', '--port', help='Target TCP Port, default 22', default=22, type=int)
    oParser.add_argument('-u', '--username', help='Target username', default='')
    oParser.add_argument('-a', '--password', help='Target password', default='')
    oParser.add_argument('-v', '--verbose', help='Verbosity; more info', action='store_true')
    dctArgs = oParser.parse_args()
    boolVerbose = dctArgs.verbose

    getBanner((dctArgs.target,dctArgs.port,boolVerbose))
    if not dctArgs.password or not dctArgs.username:
        print('[-] No password or username provided, stopping here')
        exit(0)
    
    oSSH, sPrompt = openConnection(dctArgs.target, dctArgs.port, dctArgs.username, dctArgs.password)
    
    ## Checking for CoatHanger IOC's
    ##  Source: https://github.com/JSCU-NL/COATHANGER
    print('[!] -- Checking IOC\'s for COATHANGER')
    boolPositive = False
    if checkIOCFile(oSSH, sPrompt, '/lib/liblog.so'): boolPositive = True
    # Note: if "/data/bin/smartctl" is there, it could be from an upgrade, can be ignored
    if checkIOCFile(oSSH, sPrompt, '/data/bin/smartctl'): boolPositive = True
    if checkIOCDATA2(oSSH, sPrompt): boolPositive = True
    if checkIOCTimes(oSSH, sPrompt): boolPositive = True
    if not boolPositive: print('[+] None were found for device {}'.format(dctArgs.target))

    ## Checking for IOC's for CVE-2022-42475
    ##   Source: https://community.fortinet.com/t5/FortiGate/Technical-Tip-Critical-vulnerability-Protect-against-heap-based/ta-p/239420
    print('[!] -- Checking IOC\'s for CVE-2022-42475')
    boolPositive = False
    if checkIOCFile(oSSH, sPrompt, '/data/lib/lib*'): boolPositive = True
    if checkIOCFile(oSSH, sPrompt, '/var/.sslvpnconfigbk'): boolPositive = True
    if checkIOCFile(oSSH, sPrompt, '/data/etc/wxd.conf'): boolPositive = True
    if checkIOCFile(oSSH, sPrompt, '/flash'): boolPositive = True
    if not boolPositive: print('[+] None were found for device {}'.format(dctArgs.target))

    if len(sys.argv) == 1: input('Press [Enter] key to exit')
    exit(0)

if __name__ == "__main__":
	main()
