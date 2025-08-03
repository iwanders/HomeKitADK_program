// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

#include "HAPPlatformBLEPeripheralManager+Init.h"

#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

// Use the raw HCI interface
// https://github.com/embassy-rs/trouble/blob/main/examples/linux/src/lib.rs
// https://github.com/bluez/bluez/wiki/HCI


static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "BLEPeripheralManager" };


void HAPPlatformBLEPeripheralManagerCreate(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        const HAPPlatformBLEPeripheralManagerOptions* options) {
    HAPPrecondition(blePeripheralManager);
    HAPPrecondition(options);
    HAPPrecondition(options->keyValueStore);

    blePeripheralManager->fd = 0;
    blePeripheralManager->fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, BTPROTO_HCI);
    if (blePeripheralManager->fd == 0) {
      HAPLog(&logObject, "Could not open bluetooth socket");

      HAPAssert(blePeripheralManager->fd != 0);
    }

    struct sockaddr_hci addr;

    memset(&addr, 0, sizeof(addr));
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev = 0;
    addr.hci_channel = HCI_CHANNEL_USER;

    HAPLogInfo(&logObject, "Got bluetooth socket? %d", blePeripheralManager->fd);

    int res  = bind(blePeripheralManager->fd,&addr,sizeof(addr));
    HAPLogInfo(&logObject, "bind? %d", res);

    if (res != 0) {
      HAPLog(&logObject, "Could not bind socket");

      HAPAssert(res == 0);
    }

}

void HAPPlatformBLEPeripheralManagerSetDelegate(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager_,
        const HAPPlatformBLEPeripheralManagerDelegate* _Nullable delegate_) {
    HAPPrecondition(blePeripheralManager_);


}

void HAPPlatformBLEPeripheralManagerSetDeviceAddress(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        const HAPPlatformBLEPeripheralManagerDeviceAddress* deviceAddress) {
    HAPPrecondition(blePeripheralManager);
    HAPPrecondition(deviceAddress);

    HAPLog(&logObject, __func__);
}

void HAPPlatformBLEPeripheralManagerSetDeviceName(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        const char* deviceName) {
    HAPPrecondition(blePeripheralManager);
    HAPPrecondition(deviceName);

    HAPLog(&logObject, __func__);
}

static void memrev(uint8_t* dst, const uint8_t* src, size_t n) {
    src += n;
    while (n--) {
        *dst++ = *--src;
    }
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformBLEPeripheralManagerAddService(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        const HAPPlatformBLEPeripheralManagerUUID* type,
        bool isPrimary) {
    HAPPrecondition(blePeripheralManager);
    HAPPrecondition(type);

    HAPLog(&logObject, __func__);

/*
    if (!peripheral) {
        peripheral = [[HAPBLEPeripheralDarwin alloc] init];
    }

    [peripheral addService:[[CBMutableService alloc] initWithType:uuid(type) primary:isPrimary]];
*/
    return kHAPError_None;
}

void HAPPlatformBLEPeripheralManagerRemoveAllServices(HAPPlatformBLEPeripheralManagerRef blePeripheralManager) {
    HAPPrecondition(blePeripheralManager);

    HAPLog(&logObject, __func__);

    //  [peripheral removeAllServices];
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformBLEPeripheralManagerAddCharacteristic(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        const HAPPlatformBLEPeripheralManagerUUID* type,
        HAPPlatformBLEPeripheralManagerCharacteristicProperties properties,
        const void* _Nullable constBytes,
        size_t constNumBytes,
        HAPPlatformBLEPeripheralManagerAttributeHandle* valueHandle,
        HAPPlatformBLEPeripheralManagerAttributeHandle* _Nullable cccDescriptorHandle) {
    HAPPrecondition(blePeripheralManager);
    HAPPrecondition(type);
    HAPPrecondition((!constBytes && !constNumBytes) || (constBytes && constNumBytes));
    HAPPrecondition(valueHandle);
    if (properties.notify || properties.indicate) {
        HAPPrecondition(cccDescriptorHandle);
    } else {
        HAPPrecondition(!cccDescriptorHandle);
    }

    HAPLog(&logObject, __func__);

    /*
    CBCharacteristicProperties prop = 0;
    if (properties.read)
        prop |= CBCharacteristicPropertyRead;
    if (properties.write)
        prop |= CBCharacteristicPropertyWrite;
    if (properties.writeWithoutResponse)
        prop |= CBCharacteristicPropertyWriteWithoutResponse;
    if (properties.notify)
        prop |= CBCharacteristicPropertyNotify;
    if (properties.indicate)
        prop |= CBCharacteristicPropertyIndicate;
    CBAttributePermissions perm = 0;
    if (properties.read || properties.notify || properties.indicate)
        perm |= CBAttributePermissionsReadable;
    if (properties.write || properties.writeWithoutResponse)
        perm |= CBAttributePermissionsWriteable;

    NSData* value = constBytes ? [NSData dataWithBytes:constBytes length:constNumBytes] : nil;
    CBMutableCharacteristic* characteristic = [[CBMutableCharacteristic alloc] initWithType:uuid(type)
                                                                                 properties:prop
                                                                                      value:value
                                                                                permissions:perm];
    if (properties.notify || properties.indicate) {
        *cccDescriptorHandle = [peripheral makeHandle];
    }

    *valueHandle = [peripheral addCharacteristic:characteristic];
  */

    return kHAPError_None;
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformBLEPeripheralManagerAddDescriptor(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        const HAPPlatformBLEPeripheralManagerUUID* type,
        HAPPlatformBLEPeripheralManagerDescriptorProperties properties HAP_UNUSED,
        const void* _Nullable constBytes,
        size_t constNumBytes,
        HAPPlatformBLEPeripheralManagerAttributeHandle* descriptorHandle) {
    HAPPrecondition(blePeripheralManager);
    HAPPrecondition(type);
    HAPPrecondition(constBytes && constNumBytes);
    HAPPrecondition(descriptorHandle);

    HAPLog(&logObject, __func__);

    //  NSData* value = constBytes ? [NSData dataWithBytes:constBytes length:constNumBytes] : nil;
    //  CBMutableDescriptor* descriptor = [[CBMutableDescriptor alloc] initWithType:uuid(type) value:value];
    //  *descriptorHandle = [peripheral addDescriptor:descriptor];

    return kHAPError_None;
}

void HAPPlatformBLEPeripheralManagerPublishServices(HAPPlatformBLEPeripheralManagerRef blePeripheralManager) {
    HAPPrecondition(blePeripheralManager);

    HAPLog(&logObject, __func__);



    //  [peripheral publishServices];
}

void HAPPlatformBLEPeripheralManagerStartAdvertising(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        HAPBLEAdvertisingInterval advertisingInterval,
        const void* advertisingBytes,
        size_t numAdvertisingBytes,
        const void* _Nullable scanResponseBytes,
        size_t numScanResponseBytes) {
    HAPPrecondition(blePeripheralManager);
    HAPPrecondition(advertisingInterval);
    HAPPrecondition(advertisingBytes);
    HAPPrecondition(numAdvertisingBytes);
    HAPPrecondition(!numScanResponseBytes || scanResponseBytes);

    HAPLog(&logObject, __func__);

    // CoreBluetooth automatically prepends 3 bytes for Flags to our advertisement data
    // (It adds flag 0x06: LE General Discoverable Mode bit + BR/EDR Not Supported bit)
    HAPAssert(numAdvertisingBytes >= 3);
    advertisingBytes += 3;
    numAdvertisingBytes -= 3;
    HAPAssert(numScanResponseBytes >= 2);
    scanResponseBytes += 2;
    numScanResponseBytes -= 2;
    //  NSData* advertisingData = [NSData dataWithBytes:advertisingBytes length:numAdvertisingBytes];
    //  NSData* scanResponse = [NSData dataWithBytes:scanResponseBytes length:numScanResponseBytes];
    //  [peripheral startAdvertising:advertisingInterval advertisingData:advertisingData scanResponse:scanResponse];
}

void HAPPlatformBLEPeripheralManagerStopAdvertising(HAPPlatformBLEPeripheralManagerRef blePeripheralManager) {
    HAPPrecondition(blePeripheralManager);

    HAPLog(&logObject, __func__);

    //  [peripheral stopAdvertising];
}

void HAPPlatformBLEPeripheralManagerCancelCentralConnection(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        HAPPlatformBLEPeripheralManagerConnectionHandle connectionHandle HAP_UNUSED) {
    HAPPrecondition(blePeripheralManager);

    HAPLog(&logObject, __func__);

    //  [peripheral updateCentralConnection:nil];
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformBLEPeripheralManagerSendHandleValueIndication(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        HAPPlatformBLEPeripheralManagerConnectionHandle connectionHandle,
        HAPPlatformBLEPeripheralManagerAttributeHandle valueHandle,
        const void* _Nullable bytes,
        size_t numBytes) {
    HAPPrecondition(blePeripheralManager);

    HAPLog(&logObject, __func__);


    return kHAPError_None;
}
