#! /usr/bin/python3
# -*- coding: utf-8 -*- 
r'''
	Copyright 2026 Photubias(c)

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
		
		File name docker-registry-enum.py
        written by Photubias
		
		Pulls Docker Images from unauthenticated docker registry api. 
         and checks for docker misconfigurations. 
		
		Based on & converted from:
		https://github.com/NotSoSecure/docker_fetch/blob/master/docker_image_fetch.py

        This should work on Linux & Windows using Python3
'''

import optparse, requests, urllib3, os
requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_sAPIVersion = 'v2'

def listRepos(sURL):
    oResp = requests.get(f'{sURL}/{_sAPIVersion}/_catalog', verify=False, timeout=5)
    if not oResp.status_code == 200 or not oResp.json():
        print('[-] Not a (unauthenticated) Docker Registry:\n{}'.format(oResp.text))
        exit(1)
    return oResp.json()['repositories']

def getTags(sURL, sRepo):
    oResp = requests.get(f'{sURL}/{_sAPIVersion}/{sRepo}/tags/list', verify=False)
    if 'tags' in oResp.json(): return oResp.json()['tags']
    return None

def getBlobs(sURL, sRepo, sTag):
    lstBlobList = []
    oResp = requests.get(f'{sURL}/{_sAPIVersion}/{sRepo}/manifests/{sTag}', verify=False)
    if 'fsLayers' in oResp.json():
        for dctBlob in oResp.json()['fsLayers']:
            sBlob = dctBlob['blobSum'].split(':')[-1]
            if sBlob not in lstBlobList: lstBlobList.append(sBlob)
    return lstBlobList

def downloadBlobs(sURL, sRepo, lstBlobList, sFolder):
    for sBlob in lstBlobList:
        print(f'[+] Downloading blob {sBlob}')
        oResp = requests.get(f'{sURL}/{_sAPIVersion}/{sRepo}/blobs/sha256:{sBlob}', verify=False)
        sFilename = f'{sBlob}.tar.gz'
        with open(f'{sFolder}/{sFilename}', 'wb') as oFile:
            oFile.write(oResp.content)
    return True

def main(): 
    sUsage = ('usage: %prog [options]\n'
              'Reads a given and unauthenticated Docker Registry\n'
              'List repositories and download images')
    oParser = optparse.OptionParser(sUsage)
    oParser.add_option('--url', '-u', metavar='STRING', dest='url', help='URL Endpoint for Docker Registry API v2. Eg https://IP:Port, required')
    (oOptions, lstArgs) = oParser.parse_args()
    if not oOptions.url: 
        print('[-] Please use -u option to define API Endpoint, e.g. https://IP:Port\n')
        exit(1)
    sURL = oOptions.url + '/' if oOptions.url[-1] == '/' else oOptions.url
    lstRepos = listRepos(sURL)
    
    print('[+] List of Repositories:')
    for sRepo in lstRepos: print(sRepo)

    sTargetRepo = input('\nPlease enter the name of the repo to download:  ')
    if not sTargetRepo in lstRepos:
        print('[-] No such repo found.')
        exit(1)
    lstTags = getTags(sURL, sTargetRepo)
    if lstTags is None: 
        print('[-] No such Tag Available.')
        exit(1)
    print('\n[+] Available Tags:')
    for sTag in lstTags: print(sTag)
    
    sTargetTag = input('\nPlease enter the name of the tag to download:  ')
    if not sTargetTag in lstTags:
        print('[-] No such tag found.')
        exit(1)
    lstBlobs = getBlobs(sURL, sTargetRepo, sTargetTag)
    sFoldername = f'{sTargetRepo}-{sTargetTag}'
    if os.path.exists(sFoldername): 
        print(f'[-] Folder {sFoldername} already exists.')
        exit(1)
    sAns = input('[+] Download {} blobs to folder {}? [y/N]: '.format(len(lstBlobs), sFoldername))
    if not 'y' in sAns.lower(): return
    os.makedirs(sFoldername)
    boolResult = downloadBlobs(sURL, sTargetRepo, lstBlobs, sFoldername)
    if boolResult: print('[+] All done, please extract via \n    \'for i in *.tar.gz; do tar -xzf $i; done\'')

if __name__ == '__main__':
    main()
    exit(0)
