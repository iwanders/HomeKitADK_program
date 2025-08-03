#!/bin/bash -xe
cd HomeKitADK
git restore .
git apply ../HAPOpenSSL.patch
rm PAL/Linux/{HAPPlatformBLEPeripheralManager.c,HAPPlatformBLEPeripheralManager+Init.h}
ln -r -s ../LinuxHAP/* PAL/Linux/
