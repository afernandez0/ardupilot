#!/usr/bin/bash

BOARD_NAME=MatekH743

Tools/scripts/build_bootloaders.py --signing-key=Tools/scripts/signing/ArduPilotKeys/key1_public_key.dat ${BOARD_NAME}
if [ $? -ne 0 ]; then
   echo "Bootloader"
   exit -1
fi

Tools/scripts/signing/make_secure_bl.py   Tools/bootloaders/${BOARD_NAME}_bl.bin 

if [ $? -ne 0 ]; then
   echo "Make secure"
   exit -1
fi

./waf configure --board ${BOARD_NAME} --signed-fw
if [ $? -ne 0 ]; then
   echo "waf configure"
   exit -1
fi

./waf clean
if [ $? -ne 0 ]; then
   echo "waf clean"
   exit -1
fi

./waf copter
if [ $? -ne 0 ]; then
   echo "waf copter"
   exit -1
fi



if [ -f build/${BOARD_NAME}/processed_defaults.parm ]; then
    Tools/scripts/generate_checksum.py build/${BOARD_NAME}/processed_defaults.parm
fi

# XXXX = For zero checksum 
Tools/scripts/signing/make_secure_fw.py build/${BOARD_NAME}/bin/arducopter.apj Tools/scripts/signing/private_keys/key1_private_key.dat   build/${BOARD_NAME}/processed_defaults_parm.chksum   XXXX
if [ $? -ne 0 ]; then
   echo "make secure fw"
   exit -1
fi

echo "Tools/scripts/uploader.py --port /dev/ttyACM0 build/${BOARD_NAME}/bin/arducopter.apj build/${BOARD_NAME}/bin/arducopter_apj.sign" 

