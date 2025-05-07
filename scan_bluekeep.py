#!/usr/bin/env python3

import ssl
import argparse
import sys
import traceback
import struct
import socket
import hashlib
import string
import random
import logging
import os
import sys
import concurrent.futures
from binascii import unhexlify, hexlify
from ipaddress import IPv4Network

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes

log = logging.getLogger("bluekeep")

VERSION = "0.13"

SEC_ENCRYPT = 0x08
SEC_INFO_PKT = 0x40

STATUS_VULNERABLE = "VULNERABLE"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_NORDP = "NO RDP"
STATUS_SAFE = "SAFE"

NEGOTIATION_FAILURED = ["UNKNOWN_ERROR",
    "SSL_REQUIRED_BY_SERVER", # 1
    "SSL_NOT_ALLOWED_BY_SERVER",
    "SSL_CERT_NOT_ON_SERVER",
    "INCONSISTENT_FLAGS",
    "HYBRID_REQUIRED_BY_SERVER", # 5
    "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"] # 6

# https://github.com/DavidBuchanan314/rc4
class RC4:
    """
    This class implements the RC4 streaming cipher.

    Derived from http://cypherpunks.venona.com/archive/1994/09/msg00304.html
    """

    def __init__(self, key, streaming=True):
        assert(isinstance(key, (bytes, bytearray)))

        # key scheduling
        S = list(range(0x100))
        j = 0
        for i in range(0x100):
            j = (S[i] + key[i % len(key)] + j) & 0xff
            S[i], S[j] = S[j], S[i]
        self.S = S

        # in streaming mode, we retain the keystream state between crypt()
        # invocations
        if streaming:
            self.keystream = self._keystream_generator()
        else:
            self.keystream = None

    def crypt(self, data):
        """
        Encrypts/decrypts data (It's the same thing!)
        """
        assert(isinstance(data, (bytes, bytearray)))
        keystream = self.keystream or self._keystream_generator()
        return bytes([a ^ b for a, b in zip(data, keystream)])

    def _keystream_generator(self):
        """
        Generator that returns the bytes of keystream
        """
        S = self.S.copy()
        x = y = 0
        while True:
            x = (x + 1) & 0xff
            y = (S[x] + y) & 0xff
            S[x], S[y] = S[y], S[x]
            i = (S[x] + S[y]) & 0xff
            yield S[i]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/db6713ee-1c0e-4064-a3b3-0fac30b4037b

def pdu_connection_request(use_ssl = True):
    pkt = (
        b"\x03\x00" + # TPKT header
        b"\x00\x2b" + # TPKT leangth
        # X.224 Connection Request
        b"\x26" + # length
        b"\xe0" + # CR CDT
        b"\x00\x00" + # DST-REF
        b"\x00\x00" + # SRC-REF
        b"\x00" + # CLASS OPTION = Class 0
        # Cookie: mstshash=IDENTIFIER
        b"\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d" +
        ''.join(random.choice(string.ascii_letters)
                   for i in range(5)).encode("ascii") + # "username"
        b"\x0d\x0a" +
        b"\x01" + # RDP_NEG_REQ
        b"\x00" + # flags
        b"\x08" # length
    )
    if not use_ssl:
        pkt += b"\x00\x00\x00\x00\x00" # PROTOCOL_RDP - standard security
    else:
        pkt += b"\x00\x01\x00\x00\x00" # PROTOCOL_SSL - TLS security
    return pkt


def rdp_connect(sock, use_ssl):
    ip, port = sock.getpeername()
    log.debug(f"[D] [{ip}] Verifying RDP protocol...")

    res = rdp_send_recv(sock, pdu_connection_request(use_ssl))
    # 0300 0013 0e d0 0000 1234 00
    # 03 - response type x03 TYPE_RDP_NEG_FAILURE x02 TYPE_RDP_NEG_RSP
    # 00 0800 05000000
    # Issue #2: 0300 000b 06 d0 0000 1234 00
    if res[0:2] == b'\x03\x00' and (res[5] & 0xf0) == 0xd0:
        if len(res) < 0xc or res[0xb] == 0x2:
            log.debug(f"[D] [{ip}] RDP connection accepted by the server.")
            if len(res) < 0xc:
                return "nossl"
            else:
                return None
        elif res[0xb] == 0x3:
            log.debug(f"[D] [{ip}] RDP connection rejected by the server.")
            fc = res[0xf]
            if fc > 6:
                fc = 0
            fcs = NEGOTIATION_FAILURED[fc]
            log.debug(f"[D] [{ip}] filureCode: {fcs}")
            return fcs
    raise RdpCommunicationError()


def pdu_connect_initial(use_ssl):
    pkt = (
        #000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F
        "0300" +
        "01ca" +
        "02f080" +
        "7f65" + # BER - Connect Initial
        "8201be" + # Length
        "040101" + #
        "040101" + #
        "0101ff" + # upwardFlag = TRUE
        "3020" +
        "02020022" +
        "02020002" +
        "02020000" +
        "02020001" +
        "02020000" +
        "02020001" +
        "0202ffff" +
        "02020002" +
        "3020" +
        "02020001" +
        "02020001" +
        "02020001" +
        "02020001" +
        "02020000" +
        "02020001" +
        "02020420" +
        "02020002" +
        "3020" +
        "0202ffff" +
        "0202fc17" +
        "0202ffff" +
        "02020001" +
        "02020000" +
        "02020001" +
        "0202ffff" +
        "02020002" +
        "0482014b" + # userData 0x4b length
        "000500147c00018142000800100001c00044756361" +
        "8134" +
        "01c0d800" + #CS_CORE - length 0xd8
        "04000800" + # RDP 5.0, 5.1, 5.2, 6.0, 6.1, 7.0, 7.1, 8.0, and 8.1 clients
        # When RDP 4.0 is used it does not trigger the vulnerability detection
        #"01000800" + # RDP 4.0 clients
        "2003" +
        "5802" +
        "01ca" +
        "03aa" +
        "09040000" +
        "280a0000" # client build
    )
        #000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F
    pkt += (
        "7800310038003100300000000000000000000000000000000000000000000000" + # clientName
        "04000000" + # keyboardType
        "00000000" + # keyboardSubType
        "0c000000" + # keyboardFunctionKey
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "01ca" + # postBeta2ColorDepth
        "0100" + # clientProductId
        "00000000" +
        "1800" + # highColorDepth
        "0700" + # supportedColorDepths
        "0100" + 
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "00" +
        "00")
    if use_ssl:
        pkt += "01000000" # Server selected protocol
    else:
        pkt += "00000000" # Server selected protocol
    pkt += (
        "04c00c00" + # CS_CLUSTER
        "09000000" + # CLUSTER flags
        "00000000" +
        "02c00c00" + # CS_SECURITY
        "03000000" + # encryptionMethods
        "00000000" + 
        "03c04400" + # CS_NET
        "05000000" + # Channel count
        "636c697072647200" + # cliprdr
        "c0a00000" +
        "4d535f5431323000" + # MS_T120
        "80800000" +
        "726470736e640000" + # rdpsnd
        "c0000000" +
        "736e646462670000" + # snddbg
        "c0000000" +
        "7264706472000000" + # rdpdr
        "80800000")
    return unhexlify(pkt)

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/04c60697-0d9a-4afd-a0cd-2cc133151a9c


def pdu_erect_domain_request():
    pkt = (
        b"\x03\x00" +  # header
        b"\x00\x0c" +  # length
        # X.224 Data TPDU (2 bytes: 0xf0 = Data TPDU, 0x80 = EOT, end of transmission)
        b"\x02\xf0\x80" +
        # T.125 MCS Erect Domain (PER encoding)
        b"\x04\x00\x01\x00\x01")
    return pkt

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f5d6a541-9b36-4100-b78f-18710f39f247


def pdu_attach_user_request():
    pkt = (
        b"\x03\x00" +  # header
        b"\x00\x08" +  # length
        # X.224 Data TPDU (2 bytes: 0xf0 = Data TPDU, 0x80 = EOT, end of transmission)
        b"\x02\xf0\x80" +
        b"\x28"     # PER encoded PDU contents
    )
    return pkt

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/64564639-3b2d-4d2c-ae77-1105b4cc011b


def pdu_channel_request(user1, channel_id):
    log.debug(f"Channel request '{user1}' '{channel_id}'")
    pkt = (
        b"\x03\x00" +  # header
        b"\x00\x0c" +  # length
        b"\x02\xf0\x80" +  # X.224
        b"\x38" +  # ChannelJoin request
        # network byteorder
        struct.pack('>HH', user1, channel_id)
    )
    return pkt

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9cde84cd-5055-475a-ac8b-704db419b66f


def pdu_security_exchange(rcran, rsexp, rsmod, bitlen):
    log.debug(f"Encrypting")
    encrypted_rcran_bignum = rsa_encrypt(rcran, rsexp, rsmod)
    log.debug(f"Encrypted {encrypted_rcran_bignum:0x}")
    encrypted_rcran = int_to_bytestring(encrypted_rcran_bignum)

    bitlen += 8
    bitlen_hex = struct.pack("<L", bitlen)

    log.debug(f"Encrypted client random: #{hexlify(encrypted_rcran)}")

    userdata_length = 8 + bitlen
    userdata_length_low = userdata_length & 0xFF
    userdata_length_high = userdata_length >> 8
    flags = 0x80 | userdata_length_high

    pkt = b"\x03\x00"
    pkt += struct.pack(">H", userdata_length+15)  # TPKT
    pkt += b"\x02\xf0\x80"  # X.224
    pkt += b"\x64"  # sendDataRequest
    pkt += b"\x00\x08"  # intiator userId
    pkt += b"\x03\xeb"  # channelId = 1003
    pkt += b"\x70"  # dataPriority
    pkt += struct.pack("B", flags)
    pkt += struct.pack("B", userdata_length_low)  # UserData length
    pkt += b"\x01\x00"  # securityHeader flags
    pkt += b"\x00\x00"  # securityHeader flagsHi
    pkt += bitlen_hex  # securityPkt length
    pkt += encrypted_rcran  # 64 bytes encrypted client random
    # 8 bytes rear padding (always present)
    pkt += b"\x00\x00\x00\x00\x00\x00\x00\x00"
    return pkt


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/772d618e-b7d6-4cd0-b735-fa08af558f9d
def pdu_client_info():
    pkt = (
        #000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F
        "00000000" + # CodePage
        "33010000" + # flags INFO_ENABLEWINDOWSKEY 0x100 | INFO_MOUSE 0x1 | INFO_DISABLECTRLALTDEL 0x2 |
                     # INFO_UNICODE 0x10 | INFO_MAXIMIZESHELL 0x20
        "0000" + # cbDomain
        "0a00" + # cbUserName
        "0000" + # cbPassword
        "0000" + # cbAlternateShell
        "0000" + # cbWorkingDir
        "0000" + # Domain
        "750073006500720030000000" + # UserName
        "0000" + # Password
        "0000" + # AlternateShell
        "0000" + # WorkingDir
        "0200" + # clientAddressFamily = AF_INET (2)
        "1c00" + # cbClientAddress = 0x1c = 28 bytes
        "3100390032002e003100360038002e0031002e003200300038000000" + # clientAddress
        "3c00" + # cbClientDir
        "43003a005c00570049004e004e0054005c00530079007300740065006d003300" +
        "32005c006d007300740073006300610078002e0064006c006c000000" + # clientDir
        "a4010000" + # TIME_ZONE_INFORMATION::Bias
        "4700540042002c0020006e006f0072006d0061006c0074006900640000000000" +
        "0000000000000000000000000000000000000000000000000000000000000000" + # TIME_ZONE_INFORMATION::StandardName
        "0000" + # wYear
        "0a00" + # wMonth
        "0000" + # wDayOfWeek
        "0500" + # wDay
        "0300" + # wHour
        "0000" + # wMinute
        "0000" + # wSecond
        "0000" + # wMiliseconds
        "00000000" + # TIME_ZONE_INFORMATION::StandardBias
        "4700540042002c00200073006f006d006d006100720074006900640000000000" +
        "0000000000000000000000000000000000000000000000000000000000000000" + # DaylightName
        "0000" + # wYear ...
        "0300" +
        "0000" +
        "0500" +
        "0200" +
        "0000" +
        "0000" +
        "0000" + # wMiliseconds
        "c4ffffff" + # TIME_ZONE_INFORMATION::DaylightBias
        "00000000" + # clientSessionId
        "27000000" + # performanceFlags
        "0000" # cbAutoReconnectCookie
    )
    return unhexlify(pkt)


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4c3c2710-0bf0-4c54-8e69-aff40ffcde66
def pdu_client_confirm_active():
    pkt = (
        #000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F
        # Share Control Header
        "a401" + # totalLength
        "1300" + # pduType
        "f103" + # pduSource
        "ea030100" + # shareId
        "ea03" + # originatorId
        "0600" + # lengthSourceDescriptor
        "8e01" + # lengthCombinedCapabilities
        "4d5354534300" + # sourceDescriptor
        "0e00" + # numberCapabilities
        "0000" + # pad2Octets
        "0100" + # capabilitySetType
        "1800" + # lengthCapability
        "010003000002000000000d040000000000000000" + # capabilityData
        "0200" + # capabilitySetType
        "1c00" + # lengthCapability
        "100001000100010020035802000001000100000001000000" + #capabilityData
        "0300" + # capabilitySetType
        "5800" + # lengthCapability
        "0000000000000000000000000000000000000000010014000000010047012a00" +
        "0101010100000000010101010001010000000000010101000001010100000000" +
        "a1060000000000000084030000000000e4040000" + # capabilityData
        "1300" +
        "2800" +
        "0000000378000000780000005001000000000000000000000000000000000000" +
        "00000000" +
        "0800" +
        "0a00" +
        "010014001400" +
        "0a00" +
        "0800" +
        "06000000" +
        "0700" +
        "0c00" +
        "0000000000000000" +
        "0500" +
        "0c00" +
        "0000000002000200" +
        "0900" +
        "0800" +
        "00000000" +
        "0f00" +
        "0800" +
        "01000000" +
        "0d00" +
        "5800" +
        "010000000904000004000000000000000c000000000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000000000" +
        "0c00" +
        "0800" +
        "01000000" +
        "0e00" +
        "0800" +
        "01000000" +
        "1000" +
        "3400" +
        "fe000400fe000400fe000800fe000800fe001000fe002000fe004000fe008000" +
        "fe000001400000080001000102000000")
    return unhexlify(pkt)


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2d122191-af10-4e36-a781-381e91c182b7


def pdu_client_persistent_key_list():
    pkt = (
        #000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F
        "49031700f103ea03010000013b031c0000000100000000000000000000000000" +
        "0000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaa")
    return unhexlify(pkt)


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/927de44c-7fe8-4206-a14f-e5517dc24b1c


def rdp_parse_serverdata(pkt, ip):
    ptr = 0
    rdp_pkt = pkt[0x49:]  # ..pkt.length]

    log.debug(f"[D] [{ip}] Parsing server data: {ptr}/{len(rdp_pkt)}")
    while ptr < len(rdp_pkt):
        header_type = rdp_pkt[ptr:ptr+1+1]
        header_length = struct.unpack("<H", rdp_pkt[ptr+2:ptr+3+1])[0]

        log.debug(f"[D] [{ip}] header: {hexlify(header_type)} len {header_length}")

        if header_type == b"\x02\x0c":
            log.debug(f"[D] [{ip}] security header")
            encryptionMethod = struct.unpack("<L", rdp_pkt[ptr+4:ptr+8])[0]
            encryptionLevel = struct.unpack("<L", rdp_pkt[ptr+8:ptr+12])[0]
            serverRandomLen = struct.unpack("<L", rdp_pkt[ptr+12:ptr+16])[0]
            serverCertLen = struct.unpack("<L", rdp_pkt[ptr+16:ptr+20])[0]
            log.debug(f"[D] [{ip}] encryptionMethod: {encryptionMethod:02x} encryptionLevel: {encryptionLevel:02x}")


            server_random = rdp_pkt[ptr+20:ptr+20+serverRandomLen]
            rsran = int.from_bytes(server_random, "little")

            serverCertData = rdp_pkt[ptr+20+serverRandomLen:] #ptr+20+serverRandomLen+serverCertLen]
            log.debug(f"[D] [{ip}] CertChainVersion: {serverCertData[0]:02x}")
            log.debug(f"[D] [{ip}] CertData: {hexlify(serverCertData)}")
            if serverCertData[0] == 0x02: # magic b'0\x82\x01\x15'
                log.debug(f"[D] [{ip}] Loading X.509 certificate.")
                num_certs = struct.unpack("<L", serverCertData[4:8])[0]
                log.debug(f"[D] [{ip}] Number of X.509 certificates: {num_certs}")
                ptr = 8
                while num_certs > 0:
                    cert_len = struct.unpack("<L", serverCertData[ptr:ptr+4])[0]
                    cert_data = serverCertData[ptr+4:ptr+4+cert_len]
                    log.debug(f"[D] [{ip}] cert #{num_certs} len: {cert_len} {hexlify(cert_data)}")
                    #with open(f'cert{num_certs}.crt', 'wb') as f:
                    #    f.write(cert_data)
                    cert = x509.load_der_x509_certificate(cert_data, backend=default_backend())
                    from pyasn1_modules import pem, rfc2459,rfc4055
                    from pyasn1.codec.der import decoder
                    _cert = decoder.decode(cert_data, asn1Spec=rfc2459.Certificate())[0]
                    _pub_k = _cert["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"].asOctets()
                    _pk = decoder.decode(_pub_k, asn1Spec=rfc4055.RSAPublicKey())[0]
                    _mod = int(_pk['modulus'])
                    _exp = int(_pk['publicExponent'])
                    num_certs -= 1
                    ptr += 4 + cert_len


                if _mod and _exp:
                    rsmod = _mod
                    rsexp = _exp
                    bitlen = _mod.bit_length() // 8
                else:
                    log.debug(f"[D] [{ip}] Server x509 cert isn't RSA, this scenario isn't supported (yet).")
                    raise RdpCommunicationError()
            else:
                rsa_magic = rdp_pkt[ptr+68:ptr+71+1]
                log.debug(f"[D] [{ip}] RSA magic: {rsa_magic}")
                if rsa_magic != b"RSA1":
                    log.debug(f"[D] [{ip}] Server cert isn't RSA, this scenario isn't supported (yet).")
                    raise RdpCommunicationError()
                public_exponent = rdp_pkt[ptr+84:ptr+87+1]

                bitlen = struct.unpack("<L", rdp_pkt[ptr+72:ptr+75+1])[0] - 8
                modulus = rdp_pkt[ptr+88:ptr+87+bitlen+1]
                rsmod = int.from_bytes(modulus, "little")
                rsexp = int.from_bytes(public_exponent, "little")

        ptr += header_length
        log.debug(f"[D] [{ip}] Parsing server data: {ptr}/{len(rdp_pkt)}")

    log.debug(f"[D] [{ip}] RSA len: {bitlen} bytes {bitlen*8} bits")
    log.debug(f"[D] [{ip}] SERVER_MODULUS: {rsmod:x}")
    log.debug(f"[D] [{ip}] SERVER_EXPONENT: {rsexp:x}")
    log.debug(f"[D] [{ip}] SERVER_RANDOM: {hexlify(server_random)}")

    # log.debug(f"MODULUS  = #{hexlify(modulus)} - #{rsmod.to_s}")
    # log.debug(f"EXPONENT = #{hexlify(public_exponent)} - #{rsexp.to_s}")
    # log.debug(f"SVRANDOM = #{hexlify(server_random)} - #{rsran.to_s}")

    return rsmod, rsexp, rsran, server_random, bitlen


class RdpCommunicationError(Exception):
    pass


def rdp_send(sock, data):
    sock.send(data)
    # sock.flush
    # sleep(0.1)
    # sleep(0.5)


def rdp_recv(sock):
    res1 = sock.recv(4)
    if res1 == b'':
        raise RdpCommunicationError()  # nil due to a timeout
    version = res1[0]
    if version == 3:
        l = struct.unpack(">H", res1[2:4])[0]
    else:
        l = res1[1]
        if l & 0x80:
            l &= 0x7f
            l = l * 256 + res1[2]
    if l < 4:
        raise RdpCommunicationError()
    res2 = b''
    remaining = l - 4
    log.debug(f"Received: {hexlify(res1)} to_receive: {l:04x}")
    while remaining:
        chunk = sock.recv(remaining)
        res2 += chunk
        remaining -= len(chunk)
        # log.debug(f"Received: {(len(res2)+4):04x}")
    if res2 == b'':
        raise RdpCommunicationError()  # nil due to a timeout
    log.debug(f"Received data: {hexlify(res1+res2)}")
    return res1 + res2


def rdp_send_recv(sock, data):
    rdp_send(sock, data)
    return rdp_recv(sock)


def rdp_encrypted_pkt(data, rc4enckey = None, hmackey = None, flags = 0,
                      flagsHi=0, channelId=b"\x03\xeb"):
    add_security_header = (flags & SEC_INFO_PKT) or hmackey
    add_security_header1 = hmackey

    userData_len = len(data)
    if add_security_header:
        userData_len += 4
    if add_security_header1:
        userData_len += 8
    udl_with_flag = 0x8000 | userData_len

    pkt = b"\x02\xf0\x80"  # X.224
    pkt += b"\x64"  # sendDataRequest
    pkt += b"\x00\x08"  # intiator userId .. TODO: for a functional client this isn't static
    pkt += channelId  # channelId = 1003
    pkt += b"\x70"  # dataPriority
    pkt += struct.pack(">H", udl_with_flag)
    if add_security_header:
        pkt += struct.pack("<H", flags)  # {}"\x48\x00" # flags  SEC_INFO_PKT | SEC_ENCRYPT
        pkt += struct.pack("<H", flagsHi)  # flagsHi
    if add_security_header1:
        pkt += rdp_hmac(hmackey, data)[0:7+1]
    pkt += rdp_rc4_crypt(rc4enckey, data) if rc4enckey else data

    tpkt = b"\x03\x00"
    tpkt += struct.pack(">H", len(pkt) + 4)
    tpkt += pkt

    return tpkt


def rdp_decrypt_pkt(data, rc4deckey, ip):
    # 000102030405060708090a0b0c0d0e0f1011121314151617
    # 0300002202f08068000103eb701480020000ff031000070000000200000004000000
    # 030001aa02f08068000103eb70819b08000000c560a0aa99ae9c07cd0e114203a53cb
    # 0300000902f0802180
    # 80b6fb733472f22b32a14d898a37aabd58913d001aa82451bd261
    # 808323c0c394f83989eec894d7493a2577048f16e23564d084cfd
    if not rc4deckey:
        return
    f = 0
    if data[0:2] == b'\x03\x00':
        t = data[0x07]
        log.debug(f"[D] [{ip}] Server PDU type {t:02x} {data[0:2]}")
        if t == 0x68:
            if data[0x0d] & 0x80:
                l = (data[0x0d] & 0x7f) * 256 + data[0x0e]
                s = 0x0f
            else:
                l = data[0x0d]
                s = 0x0e
            f = struct.unpack(">H", data[s:s+2])[0]
            fh = struct.unpack(">H", data[s+2:s+4])[0]
            h = data[s+4:s+4+8]
            enc_data = data[s+12:]
            log.debug(f"[D] [{ip}] Dec: len {l} flags 0x{f:04x} hash {hexlify(h)} actlen {len(enc_data)}")
    elif data[0] & 0x80: #fast-path traffic - FASTPATH_INPUT_ENCRYPTED is set
        # TODO: handle FASTPATH_INPUT_SECURE_CHECKSUM
        if data[1] & 0x80:
            s = 11
        else:
            s = 10
        enc_data = data[s:]
    else:
        return
    if (data[0] & 0x80) or (f & 0x0800):
        dec_data = rdp_rc4_crypt(rc4deckey, enc_data)
        log.debug(f"[D] [{ip}] Cypher text lenght: {len(enc_data):04x}")
        log.debug(f"[D] [{ip}] Enc: {hexlify(enc_data[:40])}")
        log.debug(f"[D] [{ip}] Dec: {hexlify(dec_data[:40])}")
        # if data[0] == 0x80:
        #    sys.exit(0)


def try_check(sock, rc4enckey, hmackey, rc4deckey, encrypt_flag):
    ip, port = sock.getpeername()
    try:
        for i in range(5):
            res = rdp_recv(sock)
            rdp_decrypt_pkt(res, rc4deckey, ip)
            log.debug(f"Ignoring #{hexlify(res)[:40]}")
    except RdpCommunicationError as ex:
        # we don't care
        pass

    for j in range(6):
        log.debug(f"Sending challange x86 .. {j}")
        # x86
        pkt = rdp_encrypted_pkt(
            unhexlify("100000000300000000000000020000000000000000000000"),
            rc4enckey, hmackey, encrypt_flag, 0, b"\x03\xed")
        rdp_send(sock, pkt)
        log.debug(f"Sending challange x64 .. {j}")
        # x64
        pkt = rdp_encrypted_pkt(
            unhexlify(
                "20000000030000000000000000000000020000000000000000000000000000000000000000000000"),
            rc4enckey, hmackey, encrypt_flag, 0, b"\x03\xed")
        rdp_send(sock, pkt)

        try:
            for i in range(1):
                res = rdp_recv(sock)
                rdp_decrypt_pkt(res, rc4deckey, ip)
                # MCS Disconnect Provider Ultimatum PDU
                if unhexlify("0300000902f0802180") in res:
                    log.debug(f"[D] [{ip}] Received #{hexlify(res)}")
                    return STATUS_VULNERABLE
        except socket.timeout as ex:
            pass
        except RdpCommunicationError as ex:
            # we don't care
            pass
    return STATUS_SAFE


def check_rdp_vuln(ip, port, use_ssl = True):
    # check if rdp is open
    try:
        try:
            sock = tcp_connect(ip, port)
        except Exception as ex:
            log.debug(f"[D] [{ip}] Exception occured during TCP connect: {ex}")
            return STATUS_NORDP
        status = rdp_connect(sock, use_ssl)
        if status in ["SSL_NOT_ALLOWED_BY_SERVER", "SSL_CERT_NOT_ON_SERVER"]:
            use_ssl = False
            try:
                log.debug(f"[D] [{ip}] RDP reconnecting without SSL")
                sock = tcp_connect(ip, port)
            except Exception as ex:
                log.debug(f"[D] [{ip}] Exception occured during TCP connect: {ex}")
                return STATUS_NORDP
            status = rdp_connect(sock, use_ssl)
        if status == "nossl":
            status = None
            use_ssl = False
        elif status:
            return status
    except Exception as ex:
        log.debug(f"[D] [{ip}] Exception occured during RDP connect: {ex}")
        return STATUS_NORDP

    if use_ssl:
        log.debug(f"[D] [{ip}] Starting TLS")

        #context = ssl.
        sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1,
                                       cert_reqs=ssl.CERT_NONE,)
        encrypt_flag = 0
        log.debug(f"[D] [{ip}] Security enabled: {sock.version()}")
    else:
        encrypt_flag = SEC_ENCRYPT

    # send initial client data
    log.debug(f"[D] [{ip}] Sending initial client data")
    res = rdp_send_recv(sock, pdu_connect_initial(use_ssl))

    if encrypt_flag:
        rsmod, rsexp, rsran, server_rand, bitlen = rdp_parse_serverdata(res, ip)

    # erect domain and attach user
    log.debug(f"[D] [{ip}] Sending erect domain request")
    rdp_send(sock, pdu_erect_domain_request())
    log.debug(f"[D] [{ip}] Sending attach user request")
    res = rdp_send_recv(sock, pdu_attach_user_request())

    user1 = struct.unpack("!H", res[9: 9+2])[0]

    # send channel requests
    log.debug(f"[D] [{ip}] Sending channel requests")
    rdp_send_recv(sock, pdu_channel_request(user1, 1009))
    rdp_send_recv(sock, pdu_channel_request(user1, 1003))
    rdp_send_recv(sock, pdu_channel_request(user1, 1004))
    rdp_send_recv(sock, pdu_channel_request(user1, 1005))
    rdp_send_recv(sock, pdu_channel_request(user1, 1006))
    rdp_send_recv(sock, pdu_channel_request(user1, 1007))
    rdp_send_recv(sock, pdu_channel_request(user1, 1008))

    #client_rand = "\xff\xee\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff"
    if encrypt_flag:
        client_rand = b"\x41" * 32
        rcran = int.from_bytes(client_rand, "little")

        log.debug(f"[D] [{ip}] Sending security exchange PDU")
        rdp_send(sock, pdu_security_exchange(rcran, rsexp, rsmod, bitlen))

        log.debug(f"[D] [{ip}] Calculating keys")
        rc4encstart, rc4decstart, hmackey, sessblob = rdp_calculate_rc4_keys(
            client_rand, server_rand)

        log.debug(f"[D] [{ip}] RC4_ENC_KEY: #{hexlify(rc4encstart)}")
        log.debug(f"[D] [{ip}] RC4_DEC_KEY: #{hexlify(rc4decstart)}")
        log.debug(f"[D] [{ip}] HMAC_KEY: #{hexlify(hmackey)}")
        log.debug(f"[D] [{ip}] SESS_BLOB: #{hexlify(sessblob)}")

        rc4enckey = RC4(rc4encstart)
        rc4deckey = RC4(rc4decstart)
    else:
        rc4enckey = None
        rc4deckey = None
        hmackey = None

    log.debug(f"[D] [{ip}] Sending client info PDU")
    res = rdp_send_recv(sock, rdp_encrypted_pkt(
        pdu_client_info(), rc4enckey, hmackey, SEC_INFO_PKT | encrypt_flag ))

    log.debug(f"[D] [{ip}] Received License packet: #{hexlify(res)}")
    rdp_decrypt_pkt(res, rc4deckey, ip)

    res = rdp_recv(sock)
    log.debug(f"[D] [{ip}] Received Server Demand packet: #{hexlify(res)}")
    rdp_decrypt_pkt(res, rc4deckey, ip)

    log.debug(f"[D] [{ip}] Sending client confirm active PDU")
    rdp_send(sock, rdp_encrypted_pkt(
        pdu_client_confirm_active(), rc4enckey, hmackey, 0x30 | encrypt_flag))

    log.debug(f"[D] [{ip}] Sending client synchronize PDU")
    log.debug(f"[D] [{ip}] Sending client control cooperate PDU")
    synch = rdp_encrypted_pkt(
        unhexlify("16001700f103ea030100000108001f0000000100ea03"), rc4enckey, hmackey, encrypt_flag)
    coop = rdp_encrypted_pkt(
        unhexlify("1a001700f103ea03010000010c00140000000400000000000000"), rc4enckey, hmackey, encrypt_flag)
    rdp_send(sock, synch + coop)

    log.debug(f"[D] [{ip}] Sending client control request control PDU")
    rdp_send(sock, rdp_encrypted_pkt(
        unhexlify("1a001700f103ea03010000010c00140000000100000000000000"), rc4enckey, hmackey, encrypt_flag))

    log.debug(f"[D] [{ip}] Sending client persistent key list PDU")
    rdp_send(sock, rdp_encrypted_pkt(
        pdu_client_persistent_key_list(), rc4enckey, hmackey, encrypt_flag))

    log.debug(f"[D] [{ip}] Sending client font list PDU")
    rdp_send(sock, rdp_encrypted_pkt(
        unhexlify("1a001700f103ea03010000010c00270000000000000003003200"), rc4enckey, hmackey, encrypt_flag))

    #log.debug("Sending base PDU")
    #rdp_send(sock, rdp_encrypted_pkt(unhexlify("030000001d0002000308002004051001400a000c840000000000000000590d381001cc"), rc4enckey, hmackey))

    #res = rdp_recv(sock)
    # vlog.debug_good("#{hexlify(res)}")

    result = try_check(sock, rc4enckey, hmackey, rc4deckey, encrypt_flag)

    if result == STATUS_VULNERABLE:
        # report_goods
        pass

    # Can't determine, but at least I know the service is running
    return result


def tcp_connect(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(5.0)
    s.connect((ip, port))
    return s


def check_host(ip, port=3389, use_ssl = True):
    status = STATUS_UNKNOWN
    try:
        try:
            status = check_rdp_vuln(ip, port, use_ssl)
        except Exception as ex:
            raise ex
    except Exception as ex:
        log.debug(f"[D] [{ip}] Exception: {ex}")
    return ip, status

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7c61b54e-f6cd-4819-a59a-daf200f6bf94
# mac_salt_key = "W\x13\xc58\x7f\xeb\xa9\x10*\x1e\xddV\x96\x8b[d"
# data_content = "\x12\x00\x17\x00\xef\x03\xea\x03\x02\x00\x00\x01\x04\x00$\x00\x00\x00"
# hmac = rdp_hmac(mac_salt_key, data_content) # == hexlified: "22d5aeb486994a0c785dc929a2855923"


def rdp_hmac(mac_salt_key, data_content):
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    pad1 = b"\x36" * 40
    pad2 = b"\x5c" * 48

    sha1.update(mac_salt_key)
    sha1.update(pad1)
    sha1.update(struct.pack("<L", len(data_content)))
    sha1.update(data_content)

    md5.update(mac_salt_key)
    md5.update(pad2)
    md5.update(sha1.digest())
    return md5.digest()

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/705f9542-b0e3-48be-b9a5-cf2ee582607f
#  SaltedHash(S, I) = MD5(S + SHA(I + S + ClientRandom + ServerRandom))


def rdp_salted_hash(s_bytes, i_bytes, clientRandom_bytes, serverRandom_bytes):
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    sha1.update(i_bytes)
    sha1.update(s_bytes)
    sha1.update(clientRandom_bytes)
    sha1.update(serverRandom_bytes)

    md5.update(s_bytes)
    md5.update(sha1.digest())
    return md5.digest()

#  FinalHash(K) = MD5(K + ClientRandom + ServerRandom)


def rdp_final_hash(k, clientRandom_bytes, serverRandom_bytes):
    md5 = hashlib.md5()

    md5.update(k)
    md5.update(clientRandom_bytes)
    md5.update(serverRandom_bytes)
    return md5.digest()


def rdp_calculate_rc4_keys(client_random, server_random):
    # preMasterSecret = First192Bits(ClientRandom) + First192Bits(ServerRandom)
    preMasterSecret = client_random[0:23+1] + server_random[0:23+1]

    #  PreMasterHash(I) = SaltedHash(preMasterSecret, I)
    #  MasterSecret = PreMasterHash(0x41) + PreMasterHash(0x4242) + PreMasterHash(0x434343)
    masterSecret = rdp_salted_hash(preMasterSecret, b"A", client_random, server_random) + rdp_salted_hash(
        preMasterSecret, b"BB", client_random, server_random) + rdp_salted_hash(preMasterSecret, b"CCC", client_random, server_random)

    # MasterHash(I) = SaltedHash(MasterSecret, I)
    # SessionKeyBlob = MasterHash(0x58) + MasterHash(0x5959) + MasterHash(0x5A5A5A)
    sessionKeyBlob = rdp_salted_hash(masterSecret, b"X", client_random, server_random) + rdp_salted_hash(
        masterSecret, b"YY", client_random, server_random) + rdp_salted_hash(masterSecret, b"ZZZ", client_random, server_random)

    # InitialClientDecryptKey128 = FinalHash(Second128Bits(SessionKeyBlob))
    initialClientDecryptKey128 = rdp_final_hash(
        sessionKeyBlob[16:31+1], client_random, server_random)

    # InitialClientEncryptKey128 = FinalHash(Third128Bits(SessionKeyBlob))
    initialClientEncryptKey128 = rdp_final_hash(
        sessionKeyBlob[32:47+1], client_random, server_random)

    macKey = sessionKeyBlob[0:15+1]

    log.debug(f"PreMasterSecret = #{hexlify(preMasterSecret)}")
    log.debug(f"MasterSecret = #{hexlify(masterSecret)}")
    log.debug(f"sessionKeyBlob = #{hexlify(sessionKeyBlob)}")
    log.debug(f"macKey = #{hexlify(macKey)}")
    log.debug(f"initialClientDecryptKey128 = #{hexlify(initialClientDecryptKey128)}")
    log.debug(f"initialClientEncryptKey128 = #{hexlify(initialClientEncryptKey128)}")

    return initialClientEncryptKey128, initialClientDecryptKey128, macKey, sessionKeyBlob


def rsa_encrypt(bignum, rsexp, rsmod):
    return pow(bignum, rsexp, rsmod)


def rdp_rc4_crypt(rc4obj, data):
    return rc4obj.crypt(data)


def int_to_bytestring(daInt):
    return daInt.to_bytes((daInt.bit_length() + 7) // 8, byteorder='little')


def configure_logging(enable_debug, logfile):
    if enable_debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
    if logfile:
        # create file handler
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        # create formatter and add it to the handlers
        formatter = logging.Formatter(
            "%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)r"
        )
        fh.setFormatter(formatter)
        log.addHandler(fh)
    # create console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s %(message)r"
    )
    ch.setFormatter(formatter)
    log.addHandler(ch)

    log.info(f"Starting {os.path.basename(__file__)} {VERSION}")
    log.info(" ".join(sys.argv))
    #abspath = os.path.abspath(__file__)
    #dname = os.path.dirname(abspath)
    #os.chdir(dname)

def getIPsFromFile(sFile):
    lstLines = open(sFile,'r').read().splitlines()
    lstIPs = []
    for sLine in lstLines: ## Line can be an IP or a CIDR
        for sIP in getIPs(sLine): lstIPs.append(sIP)
    return lstIPs

def getIPs(sCIDR): ## Could also be a single hostname
    import ipaddress
    return [str(sIP) for sIP in list(ipaddress.ip_network(sCIDR, False).hosts())]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version=f'{os.path.basename(__file__)} {VERSION}')
    parser.add_argument('-d', '--debug', action='store_true', help='verbose output')
    parser.add_argument('--notls', action='store_false', help='disable TLS security')
    parser.add_argument('-l', '--logfile', nargs="?", help='log to file')
    parser.add_argument('-w', '--workers', type=int, default=300, help='number of parallel worker tasks')
    parser.add_argument('host', nargs="*", help='List of targets (addresses or subnets or a file)')
    args = parser.parse_args()

    if not args.host:
        parser.print_help()
        return

    configure_logging(args.debug, args.logfile)
    if os.path.isfile(args.host[0]):
        print(f'[+] Parsing file {args.host[0]} for IP addresses/networks.')
        ips = getIPsFromFile(args.host[0])
    else: 
        ips = []
        for ip in args.host:
            cmd = True
            ips += [addr.exploded for addr in IPv4Network(ip, strict=False)]
    th = []
    ips = set(ips)
    log.info(f"Going to scan {len(ips)} hosts, in {args.workers} parallel tasks")
    # with progressbar.ProgressBar(max_value=len(ips)) as bar:
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        for ip in ips:
            ft_dp = executor.submit(check_host, ip, 3389, args.notls)
            th.append(ft_dp)
        for r in concurrent.futures.as_completed(th):
            ip, status = r.result()
            # if STATUS_NORDP in status:
            #    continue
            mark = '+' if status == STATUS_VULNERABLE else '-'
            log.info(f"[{mark}] [{ip}] Status: {status}")


if __name__ == "__main__":
    main()
