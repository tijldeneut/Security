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

        Of course: no warranty when the website is changed!!
'''
## The Banner
import os, sys, urllib2, cookielib, urllib
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
## New one: https://tenable-downloads-production.s3.amazonaws.com/uploads/download/file/8027/Nessus-7.1.3-debian6_amd64.deb?X-Amz-Expires=5&X-Amz-Date=20180805T095231Z&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAI4RY63TT27LQYUGQ/20180805/us-east-1/s3/aws4_request&X-Amz-SignedHeaders=host&X-Amz-Signature=ff0382bc13c09041f96809ed57158942d2f254c0c239990b27937f8052c40de3
## Or:https://tenable-downloads-production.s3.amazonaws.com/uploads/download/file/8027/Nessus-7.1.3-debian6_amd64.deb
##  with GET X-Amz-Expires=5
##           X-Amz-Date=20180805T095231Z
##           X-Amz-Algorithm=AWS4-HMAC-SHA256
##           X-Amz-Credential=AKIAI4RY63TT27LQYUGQ/20180805/us-east-1/s3/aws4_request
##           X-Amz-SignedHeaders=host
##           X-Amz-Signature=ff0382bc13c09041f96809ed57158942d2f254c0c239990b27937f8052c40de3

strNessusURL = 'https://www.tenable.com/downloads/nessus'
strDownloadID32 = ''
strDownloadID64 = ''
strAgreeURL = 'https://www.tenable.com/downloads/pages/60/downloads/{DownloadID}/get_download_file'
strNessusDownloadURL = 'https://tenable-downloads-production.s3.amazonaws.com/uploads/download/file/'

## Step1: getting AWD Download ID (e.g. 8027 for Debian AMD64 version) and a CSRF token
print('Firstly, getting the AWS Download ID ...')
cookjar = cookielib.CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookjar))
#NessusPage = urllib2.urlopen(urllib2.Request(strNessusURL, headers={'User-Agent':'Python'}))
NessusPage = opener.open(urllib2.Request(strNessusURL, headers={'User-Agent':'Python'}))
cookies = dict((cookie.name, cookie.value) for cookie in cookjar)
sessionid = cookies['_downloads_session']
for line in NessusPage.readlines():
    if 'csrf-token' in line:
        #strToken = urllib.quote_plus(line.split('content="')[1].split('"')[0])
        strToken = line.split('content="')[1].split('"')[0]
    if 'debian' in line and 'amd64.deb' in line and 'download-id' in line:
        strTheFile64bit = line.split('data-file-name="')[1].split('"')[0]
        strDownloadID64 = line.split('data-download-id="')[1].split('"')[0]
    if 'debian' in line and 'i386.deb' in line and 'download-id' in line:
        strTheFile32bit = line.split('data-file-name="')[1].split('"')[0]
        strDownloadID32 = line.split('data-download-id="')[1].split('"')[0]
## We now have sessionid out of the cookies, the strToken as the CSRF token and the DownloadID
print('Done: ' + strDownloadID64 + ' (amd64) or ' + strDownloadID32 + ' (i386)' + "\n")# + 'Token: ' + strToken + "\n")

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

## Step2: Performing a POST to https://www.tenable.com/downloads/pages/60/downloads/<DownloadID>/get_download_file
## POSTDATA =
##          utf8=%E2%9C%93
##          _method=get_download_file
##          authenticity_token=/EfkjJYqiIPRdMLCY8+nKfyNd0WgTBYXq6ZaeORI/ljZmTns7ofLSCJMAe1F0bwkz5QzQXXOVkcH9vDCvUizYw==
##          i_agree_to_tenable_license_agreement=true
##          commit=I+Agree
data = {'_method':'get_download_file', 'authenticity_token':strToken, 'i_agree_to_tenable_license_agreement':'true', 'commit':'I Agree'}
headers = {'Cookie':'_downloads_session='+sessionid,'User-Agent':None}
strAgreeURL = strAgreeURL.format(DownloadID = strDownloadID)
## Using a Proxy for trouble shooting (configure Burp):
##   import ssl,os
##   os.environ['https_proxy']='127.0.0.1:8080'
##   DownloadPage = urllib2.urlopen(urllib2.Request(strAgreeURL, urllib.urlencode(data), headers),context=ssl._create_unverified_context())
try:
    print("Downloading: "+strTheFile)
    DownloadPage = urllib2.urlopen(urllib2.Request(strAgreeURL, urllib.urlencode(data), headers))
    myFile = open(strTheFile, "wb")
    myFile.write(DownloadPage.read())
    myFile.close()
except urllib2.HTTPError, e:
    print e.fp.read()
    exit(1)

exit(0)
