#! /usr/bin/env python
''' 
	Copyright 2017 Photubias(c)

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
import os, urllib2
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
#'http://downloads.nessus.org/nessus3dl.php?file=Nessus-6.11.2-debian6_amd64.deb&licence_accept=yes&t=33cd11d53fcd00955d8affa59972bc15'
strNessusURL = 'https://www.tenable.com/products/nessus/select-your-operating-system'
strTimecheck = ''
strNessusDownloadURL = 'http://downloads.nessus.org/nessus3dl.php'

print('Firstly, getting the Timecheck token ...')
NessusPage = urllib2.urlopen(urllib2.Request(strNessusURL, headers={'User-Agent':'Python'}))
for line in NessusPage.readlines():
    if 'timecheck' in line and 'hidden' in line:
        strTimecheck = line.split('"hidden">')[1].split('<')[0]

print('Done: ' + strTimecheck + "\n")

strJson = 'https://www.tenable.com/plugins/os.json'
FileVersion = ''
FileVersionPage = urllib2.urlopen(urllib2.Request(strJson, headers={'User-Agent':'Python'}))

for line in FileVersionPage.readlines():
    if 'version' in line:
        FileVersion = line.split(':')[1].split(',')[0].replace('"','')

strTheFile32bit = 'Nessus-' + FileVersion + '-debian6_i386.deb'
strTheFile64bit = 'Nessus-' + FileVersion + '-debian6_amd64.deb'

print("What file do you want?")
print('1: ' + strTheFile32bit)
print('2: ' + strTheFile64bit + ' [default]')
ans = raw_input()
if ans == "1":
    strTheFile = strTheFile32bit
else:
    strTheFile = strTheFile64bit

strNessusDownload = strNessusDownloadURL+'?file=' + strTheFile + '&licence_accept=yes&t=' + strTimecheck
print("Downloading: "+strNessusDownload)
NessusDownload = urllib2.urlopen(urllib2.Request(strNessusDownload, headers={'User-Agent':'Python'}))
myFile = open(strTheFile, "wb")
myFile.write(NessusDownload.read())
myFile.close()

exit()
