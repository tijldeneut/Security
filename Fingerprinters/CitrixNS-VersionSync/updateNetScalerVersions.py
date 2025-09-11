#!/usr/bin/env python3
# -*- coding: utf-8 -*- 
import optparse, requests, os, urllib, json, base64, struct, hmac, time, datetime, importlib
from html.parser import HTMLParser
from html import unescape
requests.packages.urllib3.disable_warnings()        ## Needed in case of a proxy

sParseTgzFile = 'extractStampFromTgzFile.py'

class FormInputParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_form = False
        self.form_inputs = {}

    def handle_starttag(self, tag, attrs):
        if tag == 'form': self.in_form = True
        if self.in_form and tag == 'input':
            attr_dict = dict(attrs)
            name = attr_dict.get('name')
            value = attr_dict.get('value', '')
            if name: self.form_inputs[name] = value

    def handle_endtag(self, tag):
        if tag == 'form': self.in_form = False

def requestDetails(sCredFile):
    print(f'[!] Warning, first use detected. File {sCredFile} not found, will create now')
    sUsername = input('[?] Please type/paste your username, e.g. support@contoso.com : ')
    sPassword = input('[?] Please type/paste your password, e.g. MyPassword123 : ')
    sTOTPSecret = input('[?] Please type/paste your TOTP secret, if any, e.g. ABC123DEF456GHIJ : ')
    try: 
        if sTOTPSecret == '': open(sCredFile,'w').write(f'{sUsername}\n{sPassword}')
        else: open(sCredFile,'w').write(f'{sUsername}\n{sPassword}\n{sTOTPSecret}')
    except: exit(f'[-] Error while creating file {sCredFile}')
    return sCredFile

def warmupAndVerify(oSession):
    ## Warming up the Session object
    oSession.get('https://support.citrix.com')          ## Warm up the systems
    oSession.get('https://support.citrix.com/login-sso')
    dctResp = oSession.get('https://support.citrix.com/assets/config.json').json()
    if not 'wolkenMasterApiUrl' in dctResp:
        print('[-] Error A: Login method changed, I cannot work like this :-)')
        exit()
    ## Verify SSO details
    sWolkenURL = dctResp['wolkenMasterApiUrl']
    dctResp = oSession.get(f'{sWolkenURL}/company/getDomainSsoDetails',headers={'Origin':'https://support.citrix.com','Authorization':'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ7XCJhdXRoXCI6XCJzdXBwb3J0LmNpdHJpeC5jb21cIn0ifQ.RSvetgxqOZmQkiFdmXHbZA20xrsMzn5dgdu1yeDdGt2leImR2szhtrAO7W5rQyO+B_HGFghCmt91h+PoWcmtnA'}).json()
    if not 'data' in dctResp or not 'redirectUri' in dctResp['data']['companyDetails']['ssoConfiguration']:
        print('[-] Error B: Login method changed, I cannot work like this :-)')
        exit()
    sRedirectURL = dctResp['data']['companyDetails']['ssoConfiguration']['redirectUri']
    ## Got SSO details, this one should forward to "accounts.cloud.com":
    oResp = oSession.get(sRedirectURL)
    sLoginURL = oResp.url
    sResp = oResp.text
    if not 'modelJson' in sResp:
        print('[-] Error C: Login method changed, I cannot work like this :-)')
        exit()
    dctModelJson = json.loads(unescape(sResp.split('modelJson')[1].split('>')[1].split('<')[0]))
    sXSRF = dctModelJson['antiForgery']['value']
    #> TODO: This contains the XSRF cookie to be used in the actual login request, POST DATA: idsrv.xsrf=CfDJ8FVJDF-xZ3BBsTGycLOdAJCk0C-XpKx8Vsb0FWTjHEpZoDackf3h4NgXAukP6MIWqh0aohhMGq3TNAW6ASchvedtTWYdK3B9yb6l7RnPZrbTWvWqw_MayKFIBBuS-NtCVtGRmqyPCUtLkNsIogj2iK0&username=delivery.supplier%40ebo-enterprises.com&password=L2pCFKMGl3hPWGXLeahA%24&rememberMe=false
    return oSession, sLoginURL, sXSRF

def doLogin(oSession, sLoginURL, sXSRF, sUsername, sPassword, sTOTP, boolVerbose=False):
    def totp(key, time_step=30, digits=6, digest='sha1'):
        def hotp(key, counter, digits=6, digest='sha1'):
            key = base64.b32decode(key.upper() + '=' * ((8 - len(key)) % 8))
            counter = struct.pack('>Q', counter)
            mac = hmac.new(key, counter, digest).digest()
            offset = mac[-1] & 0x0f
            binary = struct.unpack('>L', mac[offset:offset+4])[0] & 0x7fffffff
            return str(binary)[-digits:].rjust(digits, '0')    
        return hotp(key, int(time.time() / time_step), digits, digest)

    dctData = {'idsrv.xsrf':sXSRF, 'username':sUsername, 'password':sPassword, 'rememberMe':'false'}
    oResp = oSession.post(sLoginURL, data=dctData)
    if not 'modelJson' in oResp.text:
        print('[-] Error D: Login method changed, I cannot work like this :-)')
        exit(1)
    dctModelJson = json.loads(unescape(oResp.text.split('modelJson')[1].split('>')[1].split('<')[0]))
    if dctModelJson['responseCode']:
        print('[-] Error: {}'.format(dctModelJson['errorMessage']))
        exit(1)
    ## If MFA is required, oResp.url will contain 'mfa'
    if 'mfa' in oResp.url.lower(): 
        dctResp = oSession.get('https://accounts.cloud.com/core/mfa/status').json()
        if 'name' in dctResp: print('[+] Username & password correct for user: {}'.format(dctResp['name']))
        sURL = 'https://accounts.cloud.com/core/mfa/challenge/login'
        dctData = {'factor':'Totp', 'code':totp(sTOTP)}
        dctResp = oSession.post(sURL, json=dctData).json()
        if 'StatusCode' in dctResp and not dctResp['StatusCode'] == 'Succeeded':
            print('[-] Error with the TOTP code: {}'.format(dctResp['Details']))
            exit(1)
        sRedirect = dctResp['redirectUri']
    ## Login to cloud.com successful, now follow redirect to SAML
    oResp = oSession.get(sRedirect)
    ## Submit State Token to external SSO
    if 'stateToken =' in oResp.text:
        sStateToken = oResp.text.split('stateToken =')[1].split('\'')[1]
        oResp = oSession.post('https://extsso.cloud.com/idp/idx/introspect', json={'stateToken':sStateToken})
        if oResp.status_code == 200: 
            dctResp = oResp.json()
            ## NOTE: interesting other data in this JSON response
            print('[+] SSO login succesful, login expires at {}'.format(dctResp['expiresAt']))
        elif 'The session has expired' in oResp.text:
            print(f'[!] Warning, rate limit detected during login, please retry (happens about 50%).')
            if boolVerbose: print(f'Error: {oResp.text}')
            exit(1)
        else: 
            print(f'[!] Warning, something might have gone wrong.')
            if boolVerbose: print(f'Error: {oResp.text}')
            exit(1)
    ## Complete the redirect process, receive a SAML Response
    oResp = oSession.get(dctResp['success']['href'])
    if not 'SAMLResponse' in oResp.text:
        print('[-] Error E: Login method changed, I cannot work like this :-)')
        exit(1)
    sSaml = unescape(oResp.text.split('"SAMLResponse"')[1].split('value="')[1].split('"')[0])
    ## Posting SAML Response
    oResp = oSession.post('https://api-csm.citrix.com/account_service/samlenduserauth?domain=support.citrix.com', data={'SAMLResponse':sSaml})
    if oResp.status_code != 200: 
        print('[-] Error posting SAML Response')
        if boolVerbose: print(f'Error: {oResp.text}')
        exit(1)
    dctResp = oSession.get('https://api-csm.citrix.com/account_service/issessionvalid',headers={'Origin':'https://support.citrix.com'}).json()
    if 'status' in dctResp and dctResp['status'] == 'success': print('[+] Entire login process completed')
    return oSession

def accessThisPage(oSession, sURL):
    oResp = oSession.get(sURL,headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0'})
    if 'response_type' in oResp.text: ## We need to request an auth-token:
        sNextURL = unescape(oResp.text.split('action=')[1].split('\'')[1])
        oParser = FormInputParser()
        oParser.feed(oResp.text)
        sNextURL += '?{}'.format(urllib.parse.urlencode(oParser.form_inputs))
        oResp = oSession.get(sNextURL,headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0'})
    return oResp

def getMostRecentNetscalerBuilds(boolVerbose=False):
    ## By default these endpoints only return the latest 12 builds (or the builds from the last 6 months)
    lstAllBuilds = []
    dctActiveMajors = requests.get('https://us-central1-citrix-product-documentation.cloudfunctions.net/issueTrackerData/versions?productId=6b16a3f0-195d-4ab2-9955-f638d57ea241',headers={'Origin':'https://docs.netscaler.com'}).json()
    for dctMajor in dctActiveMajors:
        sVersion = dctMajor['version']
        if boolVerbose: print(f'[i] Fetching latest build for NetScaler {sVersion}')
        sProductId = dctMajor['id']
        dctActiveVersions = requests.get(f'https://us-central1-citrix-product-documentation.cloudfunctions.net/issueTrackerData/builds?versionId={sProductId}',headers={'Origin':'https://docs.netscaler.com'}).json()
        for dctMinor in dctActiveVersions:
            sBuild = dctMinor['build_number']
            dtReleaseDate = datetime.datetime.strptime(dctMinor['release_date'], '%Y-%m-%dT%H:%M:%S.%fZ')
            lstAllBuilds.append((sVersion, sBuild, dtReleaseDate))
    return lstAllBuilds ## list of builds formatted as ('14.1','47.46',2025-06-13T08:18:24.000Z)

def missingBuilds(sFilepath, lstAllBuilds):
    lstMissingBuilds=[]
    dctVersionsInFile = json.load(open(sFilepath,'r'))
    for lstBuild in lstAllBuilds:
        boolExists = False
        for dctBuild in dctVersionsInFile:
            if f'{lstBuild[0]}-{lstBuild[1]}' == dctBuild['build']: boolExists = True
        if not boolExists: lstMissingBuilds.append(lstBuild)
    return lstMissingBuilds

def printList(sFilepath):
    dctVersionsInFile = json.load(open(sFilepath,'r'))
    lstTimestamps=[]
    lstUniqueEntries=[]
    print('rdx_en_date,rdx_en_stamp,version')
    for dctBuild in dctVersionsInFile:
        ## Dedupe duplicates (same build date but different build number, only keep highest build)
        if not dctBuild['timestamp'] in lstTimestamps: 
            lstTimestamps.append(dctBuild['timestamp'])
        else: 
            for x in lstUniqueEntries: 
                if x['timestamp'] == dctBuild['timestamp']: lstUniqueEntries.remove(x)
        lstUniqueEntries.append(dctBuild)
    for dctBuild in lstUniqueEntries: print('{},{},{}'.format(dctBuild['datestamp'], dctBuild['timestamp'], dctBuild['build']))
    return

def downloadFile(oSession, sURL, sDestination):
    with oSession.get(sURL, stream=True) as oResp:
        oResp.raise_for_status()
        with open(sDestination, 'wb') as oFile:
            i = 0
            for chunk in oResp.iter_content(chunk_size=8192): 
                i += 1
                if i%1000 == 100: print(f'[+] Downloaded {int(8192*i/1024/1024)} MB', end='\r')
                oFile.write(chunk)
    return sDestination

def main():
    sUsage = ('usage: %prog [options]\n'
            'This script reads a list of known Netscaler versions and verifies if any new versions have appeared\n'
            'It then proceeds to retrieve download-URLs, download the tgz files and automatic parse them\n\n'
            'Example usage (fully automated): %prog -d -s -a')
    oParser = optparse.OptionParser(usage = sUsage)
    oParser.add_option('--versionsfile', '-v', metavar='STRING', dest='versionsfile', help='JSON file with NetScaler builds, default "nsversions.json"', default='nsversions.json')
    oParser.add_option('--download', '-d', dest='download', action='store_true', help='Login and get file location. Requires credentials. Default False', default=False)
    oParser.add_option('--credentialfile', '-c', metavar='STRING', dest='credentialfile', help='Use/safe credentials to this file, default "config.ini"', default='config.ini')
    oParser.add_option('--autoparse', '-a', dest='autoparse', action='store_true', help=f'Automatic parse downloaded TGZ files, requires "{sParseTgzFile}". Default False', default=False)
    oParser.add_option('--silent', '-s', dest='silent', action='store_true', help='No questions asked, download all missing files. Default False', default=False)
    oParser.add_option('--proxy', '-p', metavar='STRING', dest='proxy', help='HTTP proxy (e.g. 127.0.0.1:8080), optional')
    oParser.add_option('--beautify', '-b', dest='beautify', action='store_true', help='when set, this prints all results to copy paste in the script. Default False', default=False)
    oParser.add_option('--verbose', dest='verbose', action='store_true', help='Verbosity. Default False', default=False)
    (oOptions,lstArgs) = oParser.parse_args()
    if oOptions.proxy: dctProxy={'https':oOptions.proxy}
    else: dctProxy = {}
    sConfig = oOptions.credentialfile
    sNSVersionsFile = oOptions.versionsfile
    boolVerbose = oOptions.verbose

    ## See if we're missing any new builds
    lstMissingBuilds = missingBuilds(sNSVersionsFile, getMostRecentNetscalerBuilds(boolVerbose)) ## lstMissingBuilds is list of lists: (('14.1','47.46',2025-06-13T08:18:24.000Z))
    if not lstMissingBuilds:
        print('[+] Good news, your version list seems up-to-date, nothing to do.')
        if oOptions.beautify: printList(sNSVersionsFile)
        return
    else:
        sList = ''
        for x in lstMissingBuilds: sList += '{}-{}, '.format(x[0],x[1])
        print(f'[+] There are {len(lstMissingBuilds)} versions missing from "{sNSVersionsFile}": {sList[:-2]}')

    if oOptions.beautify: printList(sNSVersionsFile)

    if not oOptions.download: return
    ## Verify some stuff
    if not os.path.isfile(os.path.join(sConfig)): requestDetails(sConfig)
    sUsername = open(sConfig,'r').readlines()[0].strip()
    sPassword = open(sConfig,'r').readlines()[1].strip()
    if len(open(sConfig,'r').readlines())>2: sTOTP = open(sConfig,'r').readlines()[2].strip()
    else: sTOTP = ''

    #### Get download links and download build versions
    oSession = requests.session()
    oSession.verify = False         ## Needed in case of a HTTPS proxy
    oSession.proxies = dctProxy     ## The proxy itself
    
    ## Login
    oSession, sLoginURL, sXSRF = warmupAndVerify(oSession)
    oSession = doLogin(oSession, sLoginURL, sXSRF, sUsername, sPassword, sTOTP, boolVerbose)

    ## Verifying access to a wellknown page
    sVersionURL = 'https://www.citrix.com/downloads/citrix-adc/virtual-appliances/vpx-release-14-1-51-72.html'
    oResponse = accessThisPage(oSession, sVersionURL)
    if oResponse.status_code != 200:
        print(f'[-] Access error or URL {sVersionURL} does not exist.')
        exit(1)
    
    ## Finding URL and download the first file of the page, which is usually the nCore version
    print(f'[+] Checking {len(lstMissingBuilds)} versions now')
    for lstBuild in lstMissingBuilds:
        sVersionURL = f'https://www.citrix.com/downloads/citrix-adc/firmware/release-{lstBuild[0].replace('.','-')}-build-{lstBuild[1].replace('.','-')}.html'
        oResponse = accessThisPage(oSession, sVersionURL)
        if oResponse.status_code != 200:
            print(f'[-] Access error or URL {sVersionURL} does not exist')
            if boolVerbose: print(f'{oResponse.text}')
            continue
        if 'swFilePath' in oResponse.text:
            sFilename = oResponse.text.split('swFilePath')[1].split('"')[1].split('/')[-1]
        if 'data-secureportal' in oResponse.text: 
            sDownloadURL = 'https:{}'.format(oResponse.text.split('data-secureportal')[1].split('rel=')[1].split('"')[1])
            print(f'[i] Ready to download {sFilename} from {sDownloadURL}')
            if oOptions.silent: sAns = ''
            else: sAns = input(f'Download {sFilename}? [Y/n]: ')
            if sAns == '' or sAns.lower() == 'y': 
                downloadFile(oSession, sDownloadURL, sFilename)
                if not oOptions.autoparse: print(f'[!] Done, now run "python {sParseTgzFile} {sFilename}" to extract new data for {sNSVersionsFile}')
                else:
                    if not os.path.isfile(os.path.join(sParseTgzFile)): 
                        print(f'[-] Error: file {sParseTgzFile} not found, cannot autoparse.')
                        continue
                    oParseTgz = importlib.import_module(sParseTgzFile.replace('.py',''))
                    print(f'[i] Parsing file {sFilename}, this takes some time')
                    lstResult = oParseTgz.main(sFilename).split(',')
                    print(r'{'+f'"datestamp":"{lstResult[0]}","timestamp":"{lstResult[1]}","build":"{lstResult[2]}"'+r'}')
    return

if __name__ == '__main__':
    main()
    exit(0)

