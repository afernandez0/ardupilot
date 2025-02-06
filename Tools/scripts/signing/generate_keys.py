#!/usr/bin/env python3

'''
Generate a public/private key pair using Python Cryptodome
'''

import sys
import base64

sys.path.append("modules/waf")
sys.path.append("modules/waf/waflib")

from waflib import Logs

Logs.init_log()

try:
    import Crypto
    from Crypto.PublicKey import RSA
except ImportError:
    print("Please install Python Cryptodome with '$ pip3 install pycryptodome==3.21'")
    sys.exit(1)

if Crypto.__version__ != "3.21.0":
    Logs.error("Please, install Cryptodome version 3.21.0")
    Logs.error("  Run: '$ pip3 install pycryptodome==3.21'")
    sys.exit(1)

def encode_key(ktype, key):
    return ktype + "_KEYV1:" + base64.b64encode(key).decode('utf-8')



if len(sys.argv) != 2:
    Logs.info("Usage:   generate_keys.py   BASENAME")
    sys.exit(1)


bname = sys.argv[1]

# Generate pair of keys
key = RSA.generate(2048)
private_key = key.export_key()

public_key = key.publickey().export_key()

public_fname = "%s_public_key.dat" % bname
private_fname = "%s_private_key.dat" % bname

# Save keys to files
with open(private_fname, "w") as f:
    f.write(encode_key("PRIVATE", private_key))
print("Generated %s" % private_fname)

with open(public_fname, "w") as f:
    f.write(encode_key("PUBLIC", public_key))

Logs.info("Generated %s" % public_fname)






