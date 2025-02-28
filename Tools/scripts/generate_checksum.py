#!/usr/bin/env python

import sys
import os
import subprocess as sp
# import shutil
# from pathlib import Path




""" Calculate the checksum of a file using SHA256sum Linux utility """
def calculate_checksum(in_filename : str):
    # Calculate checksum for file
    print(" ")
    print(f"Calculating Checksum of file: {in_filename}")

    cmd = ["sha256sum", "-b"]
    cmd.append(in_filename)

    proc = sp.Popen(cmd,
        stdout=sp.PIPE,
        stderr=sp.PIPE,
        universal_newlines=True,
        errors='replace',
        close_fds=False)

    proc.wait()
    if proc.returncode != 0:
        print("ERROR: Calculating checksum - sha256sum")

        for line in proc.stderr:
            sys.stdout.write(line)

        sys.exit(-1)

    for line in proc.stdout:
        # Save to a checksum file
        save_checksum(in_filename, line)


""" Save the calculated checksum in an ASCII file and binary file """
def save_checksum(in_filename: str, in_checksum: str):
    # Extract checksum. The first part
    line_parts = in_checksum.split(" ")

    pre, ext = os.path.splitext(in_filename)

    # Save the ASC file 
    new_name = in_filename.replace(".", "_") + ".asc"
    with open(new_name, "w") as nf:
        nf.write( in_checksum )  

    # Save the binary file 
    new_name = in_filename.replace(".", "_") + ".chksum"
    with open(new_name, "wb") as nf:
        nf.write( bytes.fromhex(line_parts[0]) )



if __name__ == '__main__':
    for i in range(1, len(sys.argv)):
        f = sys.argv[i]

        calculate_checksum(f)
