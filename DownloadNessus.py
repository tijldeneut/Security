#! /usr/bin/env python
''' 
	Copyright 2016 Photubias(c)

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
import os
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
#"http://downloads.nessus.org/nessus3dl.php?file=Nessus-6.8.1-debian6_amd64.deb&licence_accept=yes&t=9b11c03af02baa4129e7187179841b19"
strNessusURL = "http://www.tenable.com/products/nessus-home"
strToken = ""
strNessusDownloadURL = "http://downloads.nessus.org/nessus3dl.php"
print("What file do you want?")
print("1: Nessus-6.8.1-debian6_i386.deb")
print("2: Nessus-6.8.1-debian6_amd64.deb [default]")
ans = raw_input()
if ans == "1":
    strTheFile = "Nessus-6.8.1-debian6_i386.deb"
else:
    strTheFile = "Nessus-6.8.1-debian6_amd64.deb"

import urllib2 # Module for accessing websites

strNessusDownload = strNessusDownloadURL+"?file=" + strTheFile + "&licence_accept=yes&t=9b11c03af02baa4129e7187179841b19"
print("Downloading: "+strNessusDownload)
NessusDownload = urllib2.urlopen(strNessusDownload)
myFile = open(strTheFile, "wb")
myFile.write(NessusDownload.read())
myFile.close()

exit()
