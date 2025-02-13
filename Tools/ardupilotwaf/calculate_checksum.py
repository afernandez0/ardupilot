import sys
import os
import subprocess as sp
import shutil


from waflib import Context, Logs, Node
from waflib.Configure import conf

import embed


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


def modify_romfs(bld):
    header_filename = bld.bldnode.make_node('ap_romfs_embedded.h').abspath()
    print("**** HEADER = ", header_filename)
    # print("              ",bld.bldnode.abspath())

    last_fileindex = 99

    with open(header_filename, "r") as romfs:
        # Look for the last file
        lines = romfs.read().splitlines()
        counter = -1
        last_line = ""
        while True:
            last_line = lines[counter]
            if "};" in last_line:
                break
            counter -= 1

        # Previous line
        counter -= 1
        last_line = lines[counter]

        # Look for the last index
        last_line = last_line.replace("{", "")
        last_line = last_line.replace("}", "")
        line_parts = last_line.split(",")
        for item in line_parts:
            new_item = item.strip()
            if new_item.startswith("ap_romfs_"):
                romfs_file_parts = new_item.split("_")
                if len(romfs_file_parts) > 2:
                    last_fileindex = int(romfs_file_parts[2])
                    break

        print(f"Last file index: {last_fileindex}")

    with open(header_filename, "r+b") as romfs:

        # Add new files before 'const AP_ROMFS::embedded_file'
        romfs.seek(0)
        previous_line_position = romfs.tell()

        data_buffer = None
        for tmp_buffer_line in romfs:
            current_line = tmp_buffer_line.decode()
            if current_line.startswith("const AP_ROMFS::embedded_file"):
                # Move to previous line
                # print(f"Moving to {previous_line_position}")
                romfs.seek(previous_line_position)

                # Store the list of files
                data_buffer = romfs.readlines()

                romfs.seek(previous_line_position)

                # Insert Firmware checksum 
                first_file_index = last_fileindex + 1
                tmp_filename = os.path.join( bld.bldnode.abspath(), bld.env.AP_FIRMWARE_CHECKSUM_FILE)
                calculated_crc1 = embed.embed_file(romfs, tmp_filename, first_file_index, 
                                                    "firmware_checksum", 
                                                    bld.env.ROMFS_UNCOMPRESSED)

                second_file_index = last_fileindex + 2
                tmp_filename = os.path.join( bld.bldnode.abspath(), bld.env.AP_PARAMETERS_CHECKSUM_FILE)
                calculated_crc2 = embed.embed_file(romfs, tmp_filename, second_file_index, 
                                                    "params_checksum", 
                                                    bld.env.ROMFS_UNCOMPRESSED)

                embed.write_encode(romfs, "\n")

                for current_line in data_buffer:
                    if not current_line.startswith(b"};"):
                        romfs.write(current_line)
                    else:
                        break

                first_file_line = '{ "%s", sizeof(ap_romfs_%u),  0x%08x, ap_romfs_%u },\n' % (
                                    "firmware.chksum", first_file_index, calculated_crc1, first_file_index)
                embed.write_encode(romfs, first_file_line)
                    
                second_file_line = '{ "%s", sizeof(ap_romfs_%u),  0x%08x, ap_romfs_%u },\n' % (
                                        "params.chksum", second_file_index, calculated_crc2, second_file_index)
                embed.write_encode(romfs, second_file_line)

                embed.write_encode(romfs, "};\n")

                # End of processing 
                break

            previous_line_position = romfs.tell()


def _add_checksums_romfs(bld):
    Logs.info('')

    text('Adding signature files to ROMFS')

    from pathlib import Path

    path_to_list_romfs_files = Path("romfs_files.txt")
    if path_to_list_romfs_files.is_file():
        # file exists
        list_files_file = open("romfs_files.txt", "a+")

        # Write the file to the list of files for a further processing
        tmp_filename = os.path.join( bld.bldnode.abspath(), bld.env.AP_FIRMWARE_CHECKSUM_FILE)
        list_files_file.write(tmp_filename) 
        list_files_file.write("\n") 

        # Write the file to the list of files for a further processing
        tmp_filename = os.path.join( bld.bldnode.abspath(), bld.env.AP_PARAMETERS_CHECKSUM_FILE)
        list_files_file.write(tmp_filename) 
        list_files_file.write("\n") 

        list_files_file.close()

        header_file = bld.bldnode.make_node('ap_romfs_embedded.h').abspath()
        print("  ==== ", header_file)
        copy_header_file = header_file.replace(".", "_") + ".txt"
        print("  ==== ", copy_header_file)

        # Make a copy of the file 
        shutil.copy(header_file, copy_header_file)

        # Create new list of files
        new_list_files = bld.env.ROMFS_FILES
        new_list_files += [("params_chksum", bld.env.AP_PARAMETERS_CHECKSUM_FILE)]
        new_list_files += [("firmware_chksum", bld.env.AP_FIRMWARE_CHECKSUM_FILE)]
        print(" === ", bld.env.ROMFS_FILES)
        print(" === ", new_list_files)

        # process all files with embed
        if not embed.create_embedded_h(header_file, bld.env.ROMFS_FILES, bld.env.ROMFS_UNCOMPRESSED, False):
            bld.fatal("Failed to created ap_romfs_embedded.h")

    else:
        modify_romfs(bld)

@conf
def build_calculate_checksum(bld):
    # if not bld.env.AP_PROGRAM_AS_STLIB:
    bld.add_post_fun(_build_calculate_checksum)


@conf
def add_checksums_romfs(bld):
    bld.add_post_fun(_add_checksums_romfs)

