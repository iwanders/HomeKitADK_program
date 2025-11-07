#!/bin/bash -xe
cd HomeKitADK
rm -f PAL/Linux/{HAPPlatformBLEPeripheralManager.c,HAPPlatformBLEPeripheralManager+Init.h}
ln -f -r -s ../LinuxHAP/* PAL/Linux/
