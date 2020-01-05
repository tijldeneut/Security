#! /usr/bin/env python
''' 
	Copyright 2020 Photubias(c)

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

        This script will use the Official Tenable website and generate legal
        Nessus HomeFeed Registration Code.
        Only requirement is an internet connection to tenable.com and mailinator.com

        Of course: no warranty when either of them change their website!!
'''
## The Banner
import os
os.system('cls' if os.name == 'nt' else 'clear')
print """
[*****************************************************************************]
                --- Nessus Legal Home Key Registration ---
    This script will use the Official Tenable website and a generate legal
                      Nessus HomeFeed Registration Code.
Only requirement is an internet connection to tenable.com and mailinator.com
                               NO WARRANTIES!
______________________/-> Created By Tijl Deneut(c) <-\_______________________
[*****************************************************************************]
"""
strNessusURL = 'https://www.tenable.com/products/nessus/nessus-essentials'
strToken = ''
bInteractive = True

if len(sys.argv) > 1: bInteractive = False

## -- Create the cookies and receive CSRF token
print('--- Connecting to tenable.com')
import urllib2, cookielib
cookjar = cookielib.CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookjar))
NessusPage = opener.open(urllib2.Request(strNessusURL, headers={'User-Agent':'Python'}))
NessusResult = NessusPage.readlines()
for line in NessusResult:
    if 'token' in line and 'input' in line:
        strToken = line.split()[3].split("\"")[1]
print('Done: ' + strToken)

## -- Generate random email
print('--- Generating random e-mail')
import random, string
strRandomEmail = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(20))
strRandomEmail = strRandomEmail + '@mailinator.com'
print('[*] Using "'+strRandomEmail+'"')

## -- Request code (first_name=bla&last_name=bla&email=smdifhmsqifdhmdh%40mailinator.com&org_name=&robot=human&type=homefeed&token=M4zti%2BON6P0rXC90AFtCg1m7Tp%2BoHRQoQhJ%2Fp7gV%2Fz0%3D&country=BE&submit=Register)
print('--- Registering for a code')
import urllib
postvalues = {'first_name' : 'Mister',
          'last_name' : 'Student',
          'email' : strRandomEmail,
          'org_name' : '',
          'robot' : 'human',
          'type' : 'homefeed',
          'token' : strToken,
          'country' : 'AF',
          'submit' : 'Register'
           }
postdata = urllib.urlencode(postvalues)
NessusRegister = opener.open(urllib2.Request(strNessusURL, postdata, headers={'User-Agent':'Python'}))

## -- Opening the mailinator website
print('--- Opening browser to mailinator')
import webbrowser
strMailinatorURL = 'https://www.mailinator.com/v3/index.jsp?zone=public&query=' + strRandomEmail.split("@")[0] + '#/#inboxpane'
print('Success, opening the Mailinator webpage, please click the mail header')
print('Opening ' + strMailinatorURL)
webbrowser.open_new(strMailinatorURL)
print('')
print('--> The key should look something like AAAA-BBBB-CCCC-DDDD-EEEE')
print('Register Nessus with this key like this:')
print('/opt/nessus/sbin/nessuscli fetch --register <key>')
print('')
print('Manual Nessus update:')
print('/opt/nessus/sbin/nessuscli update --all')

if bInteractive: raw_input('When ready press [Enter] to exit')

exit(0)
