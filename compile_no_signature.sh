#!/usr/bin/bash

BOARD_NAME=MatekH743

# Compile the bootloader 
# Add the keys to the binary 
Tools/scripts/build_bootloaders.py ${BOARD_NAME}
if [ $? -ne 0 ]; then
   echo "Bootloader"
   exit -1
fi

./waf configure --board ${BOARD_NAME} -o build_firmware
if [ $? -ne 0 ]; then
   echo "waf configure"
   exit -1
fi

./waf clean
if [ $? -ne 0 ]; then
   echo "waf clean"
   exit -1
fi

./waf copter -j 4
if [ $? -ne 0 ]; then
   echo "waf copter"
   exit -1
fi

echo "Tools/scripts/uploader.py --port /dev/ttyACM0 build_firmware/${BOARD_NAME}/bin/arducopter.apj " 

