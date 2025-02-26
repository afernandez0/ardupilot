#!/usr/bin/env python

'''
script to create ap_romfs_embedded.h from a set of static files

Andrew Tridgell
May 2017
'''

import os, sys, tempfile, gzip



def calculate_checksum_file(in_filename, in_extension, in_fullname):
    print("**** Calculating checksum of params file: ", in_fullname)

    try:
        in_buffer = open(in_fullname,'rb').read()
    except Exception as e:
        print(e)
        raise Exception("Failed to read %s" % in_fullname)

    import hashlib

    h = hashlib.new('sha256')

    h.update(in_buffer)
    # print("    new buffer: [",new_buffer,"]",len(new_buffer))
    # print("    SHA256: ", h.hexdigest() )

    # # Save to a ASC file
    checksum_filename = in_filename + ".asc"
    # Reconstruct the original filename
    only_filename = os.path.basename(in_filename) + in_extension
    with open(checksum_filename, "w") as nf:
        nf.write(f"{h.hexdigest()}  {only_filename}")

    # Save to a binary file
    checksum_filename = in_filename + ".chksum"
    with open(checksum_filename, "wb") as nf:
        nf.write(h.digest())


def write_encode(out, s):
    out.write(s.encode())


def embed_file(out, f, idx, embedded_name, uncompressed):
    '''embed one file'''
    try:
        contents = open(f,'rb').read()
    except Exception:
        raise Exception("Failed to embed %s" % f)

    pad = 0
    if embedded_name.endswith("bootloader.bin"):
        # round size to a multiple of 32 bytes for bootloader, this ensures
        # it can be flashed on a STM32H7 chip
        blen = len(contents)
        pad = (32 - (blen % 32)) % 32
        if pad != 0:
            if sys.version_info[0] >= 3:
                contents += bytes([0xff]*pad)
            else:
                for i in range(pad):
                    contents += bytes(chr(0xff))
            print("Padded %u bytes for %s to %u" % (pad, embedded_name, len(contents)))

    crc = crc32(bytearray(contents))
    write_encode(out, '__EXTFLASHFUNC__ static const uint8_t ap_romfs_%u[] = {' % idx)

    compressed = tempfile.NamedTemporaryFile()
    if uncompressed:
        # ensure nul termination
        if sys.version_info[0] >= 3:
            nul = bytearray(0)
        else:
            nul = chr(0)
        if contents[-1] != nul:
            contents += nul
        compressed.write(contents)
    else:
        # compress it
        f = open(compressed.name, "wb")
        with gzip.GzipFile(fileobj=f, mode='wb', filename='', compresslevel=9, mtime=0) as g:
            g.write(contents)
        f.close()

    compressed.seek(0)
    b = bytearray(compressed.read())
    compressed.close()
    
    for c in b:
        write_encode(out, '%u,' % c)
    write_encode(out, '};\n\n');
    return crc

def crc32(bytes, crc=0):
    '''crc32 equivalent to crc32_small() from AP_Math/crc.cpp'''
    for byte in bytes:
        crc ^= byte
        for i in range(8):
            mask = (-(crc & 1)) & 0xFFFFFFFF
            crc >>= 1
            crc ^= (0xEDB88320 & mask)
    return crc

def create_embedded_h(filename, files, in_params_key, uncompressed=False):
    '''create a ap_romfs_embedded.h file'''

    out = open(filename, "wb")
    write_encode(out, '''// generated embedded files for AP_ROMFS\n\n''')

    # remove duplicates and sort
    files = sorted(list(set(files)))
    crc = {}

    # Calculate the checksum of parameters
    for i in range(len(files)):
        (name, filename) = files[i]

        pre, ext = os.path.splitext(filename)

        # Only calculate the checksum of parameter files 
        if ext == ".parm" or ext == ".param":            
            # Creates the checksum file; pre + ".chksum"
            calculate_checksum_file(pre, ext, filename)
            break

    for i in range(len(files)):
        (name, filename) = files[i]

        # ajfg
        # It skips the checksum file
        if name == in_params_key:
            pre, ext = os.path.splitext(filename)

            # Add to the key
            checksum_filename = pre + ".chksum"
            # checksum_filename = os.path.basename(pre) + ".chksum"
            try:
                crc[filename] = embed_file(out, checksum_filename, i, name, uncompressed)
            except Exception as e:
                print(e)
                return False
        else: 
            try:
                crc[filename] = embed_file(out, filename, i, name, uncompressed)
            except Exception as e:
                print(e)
                return False
        
    write_encode(out, '''const AP_ROMFS::embedded_file AP_ROMFS::files[] = {\n''')

    for i in range(len(files)):
        (name, filename) = files[i]
        if uncompressed:
            ustr = ' (uncompressed)'
        else:
            ustr = ''
        print("**** Embedding file %s:%s%s" % (name, filename, ustr))
        write_encode(out, '{ "%s", sizeof(ap_romfs_%u), 0x%08x, ap_romfs_%u },\n' % (name, i, crc[filename], i))

    write_encode(out, '};\n')
    out.close()
    return True


if __name__ == '__main__':
    import sys
    flist = []
    for i in range(1, len(sys.argv)):
        f = sys.argv[i]
        flist.append((f, f))

    create_embedded_h("/tmp/ap_romfs_embedded.h", flist, "defaults.chksum")
