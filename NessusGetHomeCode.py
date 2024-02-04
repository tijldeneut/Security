#!/usr/bin/python3
''' 
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

        This script will use the Official Tenable website and generate legal
        Nessus Essentials Registration Code.
        Only requirement is an internet connection to tenable.com and mailinator.com

        Of course: no warranty when either of them change their website :-)
'''
## The Banner
import sys
print("""
[*****************************************************************************]
                --- Nessus Legal Home Key Registration ---
    This script will use the Official Tenable website and generate & legal
                      Nessus Essentials Registration Code.
Only requirement is an internet connection to tenable.com and mailinator.com
                               NO WARRANTIES!
_______________________/-> Created By Photubias(c) <-\________________________
[*****************************************************************************]
""")
strNessusURL1 = 'https://www.tenable.com/products/nessus/nessus-essentials'
strNessusURL2 = 'https://www.tenable.com/evaluations/api/v1/nessus-essentials'
boolInteractive = True

if len(sys.argv) > 1: boolInteractive = False


## -- Create the cookies and receive CSRF token
print('--- Connecting to tenable.com')
#import urllib2, cookielib
import urllib.request, http.cookiejar
cookjar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookjar))
opener.addheaders = [('User-Agent','Python')]
NessusPage = opener.open(strNessusURL1)

## -- Generate random email
print('--- Generating random e-mail')
import random, string
strRandomEmail = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(20))
print('[*] Using "' + strRandomEmail + '@mailinator.com"')

## -- Request code
print('--- Registering for a code')
import urllib.parse
postvalues = {"first_name":"Mister","last_name":"Student","email":strRandomEmail+"@mailinator.com","phone":"","code":"","country":"BE","region":"","zip":"3052","title":"","company":"","consentOptIn":"true","essentialsOptIn":"false","pid":"","utm_source":"","utm_campaign":"","utm_medium":"","utm_content":"","utm_promoter":"","utm_term":"","alert_email":"","_mkto_trk":"","mkt_tok":"","queryParameters":"utm_promoter=&utm_source=&utm_medium=&utm_campaign=&utm_content=&utm_term=&pid=&lookbook=&product_eval=essentials","referrer":"https://www.tenable.com/products/nessus/nessus-essentials?utm_promoter=&utm_source=&utm_medium=&utm_campaign=&utm_content=&utm_term=&pid=&lookbook=&product_eval=essentials","lookbook":"","apps":["essentials"],"companySize":"","preferredSiteId":"","tempProductInterest":"Nessus Essentials","partnerId":""}
postdata = urllib.parse.urlencode(postvalues).encode()
NessusRegister = opener.open(strNessusURL2, data = postdata)
bResult =  NessusRegister.readlines()[0]
if bResult == b'{"message":"Success"}': print('[+] Registration success!')
else: print('[-] Registration error: ' + bResult.decode(errors='ignore'))

## -- Opening the mailinator website
print('--- Opening browser to mailinator')
import webbrowser
strMailinatorURL = 'https://www.mailinator.com/v4/public/inboxes.jsp?to={}'.format(strRandomEmail)
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

if boolInteractive: input('When ready press [Enter] to exit')

exit(0)
