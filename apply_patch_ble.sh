#!/bin/bash -xe
cd HomeKitADK
rm PAL/Linux/{HAPPlatformBLEPeripheralManager.c,HAPPlatformBLEPeripheralManager+Init.h}
ln -r -s ../LinuxHAP/* PAL/Linux/
