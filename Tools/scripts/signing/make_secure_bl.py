#!/usr/bin/env python3
'''
add a set of up to 10 public keys to an ArduPilot bootloader bin file
'''

import sys
import os
import base64

import struct
import binascii

sys.path.append("modules/waf")
sys.path.append("modules/waf/waflib")

from waflib import Logs

Logs.init_log()

try:
    import Crypto

    from Crypto.Signature import DSS
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA

except ImportError:
    Logs.error("Please install Python Cryptodome with '$ pip3 install pycryptodome==3.21'")
    sys.exit(1)

if Crypto.__version__ != "3.21.0":
    Logs.error("Please, install Cryptodome version 3.21.0")
    Logs.error("  Run: '$ pip3 install pycryptodome==3.21'")
    sys.exit(1)


# get command line arguments
from argparse import ArgumentParser


def decode_key(ktype, key):
    ktype += "_KEYV1:"
    if not key.startswith(ktype):
        print("Invalid key type")
        sys.exit(1)
    return base64.b64decode(key[len(ktype):])


parser = ArgumentParser(description='make_secure_bl')

parser.add_argument("--omit-ardupilot-keys", action='store_true', default=False, help="omit ArduPilot signing keys")
parser.add_argument("bootloader", type=str, default=None, help="bootloader")
parser.add_argument("keys", nargs='*', type=str, default=[], help="keys")
args = parser.parse_args()
    
descriptor = b'\x4e\xcf\x4e\xa5\xa6\xb6\xf7\x29'
max_keys = 10
key_len = 32

img = open(args.bootloader, 'rb').read()

offset = img.find(descriptor)
if offset == -1:
    Logs.error("Failed to find %s ECC_RAW struct" % descriptor)
    sys.exit(1)

offset += 8
Logs.debug("OFF: ", hex(offset))
desc = b''
desc_len = 0

keys = []

if not args.omit_ardupilot_keys:
    Logs.info("Adding ArduPilot keys")

    signing_dir = os.path.dirname(os.path.realpath(__file__))
    keydir = os.path.join(signing_dir,"ArduPilotKeys")
    for root, dirs, files in os.walk(keydir):
        for f in files:
            if f.endswith(".dat"):
                keys.append(os.path.relpath(os.path.join(keydir, f)))

keys += args.keys[:]

if len(keys) > max_keys:
    Logs.error("Too many key files %u, max is %u" % (len(keys), max_keys))
    sys.exit(1)

if len(keys) <= 0:
    Logs.error("At least one key file required")
    sys.exit(1)

for kfile in keys:
    read_key = decode_key("PUBLIC", open(kfile, "r").read())
    key = RSA.import_key(read_key)

    if len(key) != key_len:
        Logs.error("Bad key length %u in %s" % (len(key), kfile))
        sys.exit(1)

    Logs.info("Applying Public Key %s" % (kfile))

    desc += key
    desc_len += key_len

# Write the updated file
img = img[:offset] + desc + img[offset+desc_len:]
open(sys.argv[1], 'wb').write(img)
