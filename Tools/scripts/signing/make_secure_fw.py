#!/usr/bin/env python3
'''
sign an ArduPilot APJ firmware with a private key
'''

import binascii
import shutil
import sys
import os
import struct
import json, base64, zlib
from pathlib import Path

sys.path.append("modules/waf")
sys.path.append("modules/waf/waflib")

sys.path.append("Tools/ardupilotwaf/")

from waflib import Logs

import embed

Logs.init_log()

try:
    import Crypto

    # from Crypto.Signature import DSS
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Signature import pkcs1_15 # Digital signing alg

except ImportError:
    print("Please install Python Cryptodome with '$ pip3 install pycryptodome==3.21'")
    sys.exit(1)

if Crypto.__version__ != "3.21.0":
    Logs.error("Please, install Cryptodome version 3.21.0")
    Logs.error("  Run: '$ pip3 install pycryptodome==3.21'")
    sys.exit(1)


def to_unsigned(i):
    '''convert a possibly signed integer to unsigned'''
    if i < 0:
        i += 2**32
    return i

def decode_key(ktype, key):
    ktype += "_KEYV1:"

    if not key.startswith(ktype):
        Logs.error("Invalid key type")
        sys.exit(1)

    return base64.b64decode(key[len(ktype):])

""" Save the calculated checksum in an ASCII file and binary file """
def save_checksum(in_filename: str, in_checksum: any):
    pre, ext = os.path.splitext(in_filename)

    # Save the ASC file 
    new_name = in_filename.replace(".", "_") + ".asc"
    with open(new_name, "w") as nf:
        nf.write( f"{in_checksum.hexdigest()}  {in_filename}")  

    # Save the binary file 
    binary_name = in_filename.replace(".", "_") + ".chksum"
    with open(binary_name, "wb") as nf:
        # nf.write( bytes.fromhex(line_parts[0]) )
        nf.write(in_checksum.digest())

    return binary_name
        

def save_signature(in_filename: str, in_signature: any):
    pre, ext = os.path.splitext(in_filename)

    # Save the ASC file 
    new_name = in_filename.replace(".", "_") + ".sign.asc"
    with open(new_name, "w") as nf:
        nf.write( f"{in_signature.hex()}  {in_filename}")  

    # Save the binary file 
    binary_name = in_filename.replace(".", "_") + ".sign"
    with open(binary_name, "wb") as nf:
        # nf.write( bytes.fromhex(line_parts[0]) )
        nf.write(in_signature)

    return binary_name 


def get_checksums(in_firmware_digest):
    output_buffer = b''

    # Insert Firmware Checksum
    print("*** Adding the Firmware checksum")

    output_buffer = struct.pack("<32s", digest.digest())
    # print(digest.hexdigest())

    # Insert Default Parameters checksum
    tmp_params = [0x0] * 32
    if sys.argv[3] is not None:   
        print() 
        print("*** Adding the Defaults checksum")

        checksum_buffer = None
        with open(sys.argv[3], "rb") as chk_file:
            checksum_buffer = chk_file.read()

        ba = bytearray(checksum_buffer)
        tmp_params = struct.pack("<32s", ba)
        # print(ba.hex())
    
    output_buffer = output_buffer + tmp_params
    # print(output_buffer)
    # print(len(output_buffer))

    if len(output_buffer) != 64:
        print("ERROR: Incorrect chekcsums length")
        sys.exit(-1)

    return output_buffer


# =============================================================
# =============================================================

if len(sys.argv) != 4 and len(sys.argv) != 5:
    print("Usage: make_secure_fw.py   APJ_FILE   PRIVATE_KEYFILE    DEFAULTS_CHK_FILE")
    print(" ")
    print("Where: ")
    print("  APJ_FILE. Filename and path of the firmware in APJ format")
    print("  PRIVATE_KEY_FILE. Key file must be generated with 'generate_keys.py' script")
    print("  DEFAULTS_CHK_FILE. Default parameters checksum file")
    print(" ")
    # $ Tools/scripts/signing/make_secure_fw.py build/CubeOrange/bin/arducopter.apj  aa_private_key.dat   build/CubeOrange/bin/arducopter_apj.chksum 
    # checksum file = build/CubeOrange/bin/arducopter_apj.chksum 
    sys.exit(1)


# 2048 bits (256 bytes)
key_len = 256
sig_len = 256

# NOTE: Should these two values updated for RSA 2048?
sig_version = 30437
# Signed descriptor 
descriptor = b'\x41\xa3\xe5\xf2\x65\x69\x92\x07'

apj_file = sys.argv[1]
key_file = sys.argv[2]

# open apj file (firmware file)
apj = open(apj_file, 'r').read()

# decode json in apj
d = json.loads(apj)

# get image data
img = zlib.decompress(base64.b64decode(d['image']))
img_len = len(img)
print("Image size: ", len(img))

read_key = decode_key("PRIVATE", open(key_file, 'r').read())
private_key = RSA.import_key(read_key)

if private_key.size_in_bytes() != key_len:
    Logs.error("Bad key length: %u   Expected: %u" % (private_key.size_in_bytes(), key_len))
    sys.exit(1)

offset = img.find(descriptor)
if offset == -1:
    Logs.error("No Signed App Descriptor found")
    sys.exit(1)

offset += 8
# ajfg
# NOTE: Previous 92 = 16 + 76 (siglen, sigver, sig) 
#       Now     348 = 16 + 268 (siglen, sigver, sig) + 64 (two checksums)
desc_len = 348

digest = SHA256.new(img[:offset] + img[offset+desc_len:])
signer = pkcs1_15.new(private_key)
signature = signer.sign(digest)

signature_orig = signature

siglen = to_unsigned(len(signature))
# Note: Previous 72 = 8 + 64 (sigver, sig)
#       Now     264 = 8 + 256
signature += bytes(bytearray([0 for i in range(264 - len(signature))]))

if siglen != sig_len:
    print("Bad signature length %u should be %u" % (siglen, sig_len))
    sys.exit(1)

# Store the signature
#pack signature in 4 bytes and length into 72 byte array
# Note: length (4 bytes), signature (256 bytes) padded with zeros up to 264 bytes
desc = struct.pack("<IQ256s", sig_len+8, sig_version, signature)

# Extract the two checksums; 64 bytes 
packed_chksums = get_checksums(digest)

if sys.argv[4] is not None:
    packed_chksums = [0x0] * 64
    packed_chksums = bytearray(packed_chksums)

# 16 bytes = descriptor, crc1, crc2, img_size, git_hash
img = img[:(offset + 16)] + desc + packed_chksums + img[(offset + desc_len):]
if len(img) != img_len:
    Logs.error("Error: Image length changed: " % (len(img), img_len))
    sys.exit(1)

Logs.info("Applying APP_DESCRIPTOR Signature %d %s" % (siglen, binascii.hexlify(desc)))

d["image"] = base64.b64encode(zlib.compress(img,9)).decode('utf-8')
d["image_size"] = len(img)
d["flash_free"] = d["flash_total"] - d["image_size"]
d["signed_firmware"] = True

# Write the new firmware file
f = open(sys.argv[1], "w")
f.write(json.dumps(d, indent=4))
f.close()

Logs.info("APJ file updated: %s" % apj_file)

# Calculate the SHA256 of the whole image
# complete_digest = SHA256.new(img)

# Save the new firmware checksum
checksum_file = save_checksum(apj_file, digest)

# Save the signature
signature_file = save_signature(apj_file, signature_orig)
Logs.info("Firmware signature saved into file: %s", signature_file)

open("new_boot.bin", 'wb').write(img)




