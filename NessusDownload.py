#!/usr/bin/python3
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

        File name GetNessusHomeCode.py
        written by Photubias(c)

        This script will use the Official Tenable website and download Nessus
        Only requirement is an internet connection to tenable.com

        Of course: no warranty in case the API is changed
	Run with any extra parameter to download (x64), install and 
            generate the startup script
'''
## The Banner
import os, sys, json, urllib.request, http.cookiejar
print(r'''
[*****************************************************************************]
                  --- Nessus Linux Debian deb downloader ---
               This script will use the Official Tenable website.
            Only requirement is an internet connection to tenable.com
                               NO WARRANTIES!
______________________/-> Created By Tijl Deneut(c) <-\_______________________
[*****************************************************************************]
''')

strNessusURL = 'https://www.tenable.com/downloads/api/v1/public/pages/nessus'
strDownloadID32 = ''
strDownloadID64 = ''
strAgreeURL = r'https://www.tenable.com/downloads/pages/60/downloads/{DownloadID}/get_download_file'
strNessusDownloadURL = r'https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/xxxxxx/download?i_agree_to_tenable_license_agreement=true'
bInteractive = True

if len(sys.argv) > 1:
    bInteractive = False
    print('--- Extra argument detected.')
    print('     Performing x64 download AND installation AND script creation')

## Step0: get file names
print('--- Getting filenames...')
cookjar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookjar))
opener.addheaders = [('User-Agent','Python')]
NessusList = opener.open(strNessusURL)
jsonArr = json.loads(NessusList.read())
for el in jsonArr['downloads']:
    if 'Debian' in el['description'] and '32-bit' in el['description']:
        try: strFile32bit ## If already defined, do not overwrite var
        except NameError:
            strFile32bit = el['file']
            strFile32bitID = str(el['id'])
    if 'Debian' in el['description'] and 'AMD64' in el['description']:
        try: strFile64bit
        except NameError:
            strFile64bit = el['file']
            strFile64bitID = str(el['id'])
if bInteractive:
    print('--- What file do you want?')
    if strFile32bit: print('1: ' + strFile32bit + ' (id ' + strFile32bitID + ')')
    if strFile64bit: print('2: ' + strFile64bit + ' (id ' + strFile64bitID + ') [default]')
    ans = input('[?] : ')
if bInteractive and ans == '1':
    strTheFile = strFile32bit
    strDownloadID = strFile32bitID
else:
    strTheFile = strFile64bit
    strDownloadID = strFile64bitID

## Step2: download
strNessusDownloadURL = strNessusDownloadURL.replace('xxxxxx',strDownloadID)
try:
    print('--- Downloading: ' + strTheFile)
    #DownloadPage = urllib2.urlopen(urllib2.Request(strNessusDownloadURL, headers={'User-Agent':'Python'}))
    DownloadPage = opener.open(strNessusDownloadURL)
    myFile = open(strTheFile, "wb")
    myFile.write(DownloadPage.read())
    myFile.close()
except:
    print(sys.exc_info()[0])
    exit(1)
if bInteractive:
    print('      Run "dpkg -i ' + strTheFile + '" to install.')
else: ## Installing and creating script
    print('--- Starting installation ...')
    os.system('dpkg -i ' + strTheFile + ' && rm ' + strTheFile)
    os.system('echo \#\!/bin/bash >startNessus.sh')
    os.system('echo sudo service nessusd start >>startNessus.sh')
    os.system('echo "firefox https://127.0.0.1:8834 &" >>startNessus.sh')
    os.system('chmod +x startNessus.sh')
print('--- All done')
exit(0)
