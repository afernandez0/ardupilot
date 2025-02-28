import sys
import os
import subprocess as sp
import shutil
from pathlib import Path

from waflib import Context, Logs, Node
from waflib.Configure import conf



def text(label, text=''):
    text = text.strip()
    if text:
        Logs.info('%s%s%s%s%s' % (
            Logs.colors.NORMAL,
            Logs.colors.BOLD,
            label,
            Logs.colors.NORMAL,
            text))
    else:
        Logs.info('%s%s%s' % (
            Logs.colors.NORMAL,
            Logs.colors.BOLD,
            label
        ))


""" Calculate the checksum of a file using SHA256sum Linux utility """
def calculate_checksum(in_filename : str):
    # Calculate checksum for file
    text(" ")
    text(f"   File: {in_filename}")

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
        text("ERROR: Calculating checksum - sha256sum")

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
        


"""Calculate the checksum of all files in the 'bin' folder"""
def _build_calculate_checksum(bld):
    Logs.info('')

    text('Calculating checksum of binary files')

    build_directory = os.path.join( bld.bldnode.abspath(), "bin" )
    text('   Binaries directory: ', build_directory)
    
    # Get all files
    for filename in os.listdir(build_directory):
        pre, ext = os.path.splitext(filename)

        # Skip chksum files 
        if ext != None and (ext == ".chksum" or ext == ".asc"):
           text("   Skipping existing chksum file: ", filename)
           continue

        calculate_checksum( os.path.join( build_directory, filename) )


@conf
def build_calculate_checksum(bld):
    # if not bld.env.AP_PROGRAM_AS_STLIB:
    bld.add_post_fun(_build_calculate_checksum)

