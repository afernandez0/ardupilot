#!/usr/bin/bash

BOARD_NAME=MatekH743

# Compile the bootloader 
# Add the keys to the binary 
Tools/scripts/build_bootloaders.py ${BOARD_NAME} --signing-key=Tools/scripts/signing/ArduPilotKeys/key1_public_key.dat 
if [ $? -ne 0 ]; then
   echo "Bootloader"
   exit -1
fi

# Compile and sign the firmware
./waf configure --board ${BOARD_NAME} --signed-fw --enable-check-firmware -o build_firmware
if [ $? -ne 0 ]; then
   echo "waf configure"
   exit -1
fi

./waf clean
if [ $? -ne 0 ]; then
   echo "waf clean"
   exit -1
fi

./waf copter -j 4 --check-verbose
if [ $? -ne 0 ]; then
   echo "waf copter"
   exit -1
fi

# Add the default parameters checksum, if any
if [ -f build/${BOARD_NAME}/processed_defaults.parm ]; then
    Tools/scripts/generate_checksum.py build_firmware/${BOARD_NAME}/processed_defaults.parm
fi

# XXXX = For zero checksum 
Tools/scripts/signing/make_secure_fw.py build_firmware/${BOARD_NAME}/bin/arducopter.apj Tools/scripts/signing/private_keys/key1_private_key.dat   build_firmware/${BOARD_NAME}/processed_defaults_parm.chksum   XXXX
if [ $? -ne 0 ]; then
   echo "make secure fw"
   exit -1
fi

# Command for uploading the new Firmware
echo "Tools/scripts/uploader.py --port /dev/ttyACM0 build_firmware/${BOARD_NAME}/bin/arducopter.apj build_firmware/${BOARD_NAME}/bin/arducopter_apj.sign" 

