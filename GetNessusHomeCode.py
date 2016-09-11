#! /usr/bin/env python
''' 
	Copyright 2015 Photubias(c)

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

        Off course: no warranty when either of them change their website!!
'''
## The Banner
import os
os.system('cls' if os.name == 'nt' else 'clear')
print """
[*****************************************************************************]
                --- Nessus Legal Home Key Registration ---
    This script will use the Official Tenable website and generate legal
                      Nessus HomeFeed Registration Code.
Only requirement is an internet connection to tenable.com and mailinator.com
                               NO WARRANTIES!
______________________/-> Created By Tijl Deneut(c) <-\_______________________
[*****************************************************************************]
"""
strNessusURL = "http://www.tenable.com/products/nessus-home"
strToken = ""

import urllib2 # Module for accessing websites

## -- First get a Token
print("Firstly, get a token ...")
NessusPage = urllib2.urlopen(strNessusURL)
NessusResult = NessusPage.readlines()
for line in NessusResult:
    if 'token' in line and 'input' in line:
        strToken = line.split()[3].split("\"")[1]
print("Done: "+strToken)

## -- Then register for a key, we need a random value
import random, string
strRandomEmail = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(20))
strRandomEmail = strRandomEmail+"@mailinator.com"
#print(strRandomEmail)

print("Secondly, let's request a code, using this emailaddress: ")
print(strRandomEmail)
## - Request the key
import urllib
postvalues = {'first_name' : 'Mister',
          'last_name' : 'Student',
          'email' : strRandomEmail,
          'country' : 'AF',
          'Accept' : 'Agree',
          'robot' : 'human',
          'type' : 'homefeed',
          'token' : strToken,
          'submit' : 'Register',
    }
postdata = urllib.urlencode(postvalues)
request = urllib2.Request(strNessusURL, postdata)
response = urllib2.urlopen(request)
#print(response.read())

## -- Opening the mailinator website
import webbrowser
#strMailinatorURL = "http://www.mailinator.com/inbox.jsp?to="+strRandomEmail.split("@")[0]
strMailinatorURL = "http://www.mailinator.com/inbox2.jsp?public_to="+strRandomEmail.split("@")[0]
print("Success, opening the Mailinator webpage, please click the mail header")
print("Opening "+strMailinatorURL)
webbrowser.open_new(strMailinatorURL)
print("")
print("--> The key should look something like AAAA-BBBB-CCCC-DDDD-EEEE")
print("Register Nessus with this key like this:")
print("/opt/nessus/sbin/nessuscli fetch --register <key>")
print("")
print("Manual Nessus update:")
print("/opt/nessus/sbin/nessuscli update --all")

raw_input('When ready press [Enter] to exit')
