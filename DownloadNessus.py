#! /usr/bin/env python
''' 
	Copyright 2018 Photubias(c)

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
        written by tijl[dot]deneut[at]howest[dot]be

        This script will use the Official Tenable website and download Nessus
        Only requirement is an internet connection to tenable.com

        Off course: no warranty when the website is changed!!
'''
## The Banner
import os, sys, urllib2
os.system('cls' if os.name == 'nt' else 'clear')
print """
[*****************************************************************************]
                  --- Nessus Linux Debian deb downloader ---
               This script will use the Official Tenable website.
            Only requirement is an internet connection to tenable.com
                               NO WARRANTIES!
______________________/-> Created By Tijl Deneut(c) <-\_______________________
[*****************************************************************************]
"""
#'https://tenable-downloads-production.s3.amazonaws.com/uploads/download/file/7480/Nessus-7.0.1-debian6_amd64.deb'
strNessusURL = 'https://www.tenable.com/products/nessus/select-your-operating-system'
strDownloadID32 = ''
strDownloadID64 = ''
strNessusDownloadURL = 'https://tenable-downloads-production.s3.amazonaws.com/uploads/download/file/'

print('Firstly, getting the AWS Download ID ...')
NessusPage = urllib2.urlopen(urllib2.Request(strNessusURL, headers={'User-Agent':'Python'}))
for line in NessusPage.readlines():
    if 'debian' in line and 'amd64.deb' in line and 'download-id' in line:
        strTheFile64bit = line.split('data-file-name="')[1].split('"')[0]
        strDownloadID64 = line.split('data-download-id="')[1].split('"')[0]
    if 'debian' in line and 'i386.deb' in line and 'download-id' in line:
        strTheFile32bit = line.split('data-file-name="')[1].split('"')[0]
        strDownloadID32 = line.split('data-download-id="')[1].split('"')[0]

print('Done: ' + strDownloadID64 + ' (amd64) or ' + strDownloadID32 + ' (i386)' + "\n")

if len(sys.argv) < 2:
    print("What file do you want?")
    print('1: ' + strTheFile32bit)
    print('2: ' + strTheFile64bit + ' [default]')
    ans = raw_input()
if (len(sys.argv) > 1 and sys.argv[1] == '32') or ans == '1':
    strTheFile = strTheFile32bit
    strDownloadID = strDownloadID32
else:
    strTheFile = strTheFile64bit
    strDownloadID = strDownloadID64

strNessusDownload = strNessusDownloadURL + strDownloadID + '/' + strTheFile
print("Downloading: "+strNessusDownload)
NessusDownload = urllib2.urlopen(urllib2.Request(strNessusDownload, headers={'User-Agent':'Python'}))
myFile = open(strTheFile, "wb")
myFile.write(NessusDownload.read())
myFile.close()

exit()
