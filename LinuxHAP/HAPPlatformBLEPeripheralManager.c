// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

#include "HAPAssert.h"
#include "HAPPlatformBLEPeripheralManager+Init.h"

#include <stdint.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <pthread.h>
#include <glib.h>
#include <stdio.h>
#include <signal.h>
#include "binc/adapter.h"
#include "binc/device.h"
#include "binc/logger.h"
#include "binc/agent.h"
#include "binc/application.h"
#include "binc/advertisement.h"
#include "binc/utility.h"
#include "binc/parser.h"

#define HTS_SERVICE_UUID "00001809-0000-1000-8000-00805f9b34fb"
// Use the raw HCI interface
// https://github.com/embassy-rs/trouble/blob/main/examples/linux/src/lib.rs
// https://github.com/bluez/bluez/wiki/HCI

// https://github.com/bluez/bluez/blob/2c0c323d08357a4ff3065fcd49fee0c83b5835cd/unit/test-gatt.c#L675

// https://github.com/bluez/bluez/blob/2c0c323d08357a4ff3065fcd49fee0c83b5835cd/tools/btgatt-server.c#L648

static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "BLEPeripheralManager" };

struct LoopRunContext{
  GMainLoop *main_loop;
  GMainContext *main_context;
};

void run_main_loop(void *data) {
    struct LoopRunContext* d = data;
    g_main_context_push_thread_default(d->main_context);
    g_main_loop_run(d->main_loop);
    g_main_context_pop_thread_default(d->main_context);
}

typedef struct OurBLEContainer {


  GDBusConnection * dbusConnection;
  GMainLoop *loop;
  Adapter *default_adapter;
  Advertisement *advertisement;
  Application *app;
  Agent *agent;

} OurBLEContainer;


void on_powered_state_changed(Adapter *adapter, gboolean state) {
    OurBLEContainer* c = binc_adapter_get_user_data(adapter);
    HAPLogInfo(&logObject, "powered '%s' (%s)", state ? "on" : "off", binc_adapter_get_path(adapter));
    // HAPLogInfo(&logObject, "%s%s", prefix, str);
}

void on_central_state_changed(Adapter *adapter, Device *device) {
  OurBLEContainer* c = binc_adapter_get_user_data(adapter);

    char *deviceToString = binc_device_to_string(device);
    HAPLogInfo(&logObject, deviceToString);
    g_free(deviceToString);

    HAPLogInfo(&logObject, "remote central %s is %s", binc_device_get_address(device), binc_device_get_connection_state_name(device));
    ConnectionState state = binc_device_get_connection_state(device);
    if (state == BINC_CONNECTED) {
        binc_adapter_stop_advertising(adapter, c->advertisement);
    } else if (state == BINC_DISCONNECTED){
        binc_adapter_start_advertising(adapter, c->advertisement);
    }
}

// This function is called when a read is done
// Use this to set the characteristic value if it is not set or to reject the read request
const char *on_local_char_read(const Application *application, const char *address, const char *service_uuid,
                        const char *char_uuid) {
                          //OurBLEContainer* c = binc_adapter_get_user_data(adapter);
    /*
    if (g_str_equal(service_uuid, HTS_SERVICE_UUID) && g_str_equal(char_uuid, TEMPERATURE_CHAR_UUID)) {
        const guint8 bytes[] = {0x06, 0x6f, 0x01, 0x00, 0xff, 0xe6, 0x07, 0x03, 0x03, 0x10, 0x04, 0x00, 0x01};
        GByteArray *byteArray = g_byte_array_sized_new(sizeof(bytes));
        g_byte_array_append(byteArray, bytes, sizeof(bytes));
        binc_application_set_char_value(application, service_uuid, char_uuid, byteArray);
        g_byte_array_free(byteArray, TRUE);
        return NULL;
    }*/
    return BLUEZ_ERROR_REJECTED;
}

// This function should be used to validate or reject a write request
const char *on_local_char_write(const Application *application, const char *address, const char *service_uuid,
                          const char *char_uuid, GByteArray *byteArray) {
    GString *result = g_byte_array_as_hex(byteArray);
    HAPLogInfo(&logObject, "write request characteristic <%s> with value <%s>", char_uuid, result->str);
    g_string_free(result, TRUE);

    return NULL;
}

// This function is called after a write request was validates and the characteristic value was set
void on_local_char_updated(const Application *application, const char *service_uuid,
                           const char *char_uuid, GByteArray *byteArray) {
    GString *result = g_byte_array_as_hex(byteArray);
    HAPLogInfo(&logObject, "characteristic <%s> updated to <%s>", char_uuid, result->str);
    g_string_free(result, TRUE);
}

void on_local_char_start_notify(const Application *application, const char *service_uuid, const char *char_uuid) {
    HAPLogInfo(&logObject, "on start notify");
    /*if (g_str_equal(service_uuid, HTS_SERVICE_UUID) && g_str_equal(char_uuid, TEMPERATURE_CHAR_UUID)) {
        const guint8 bytes[] = {0x06, 0x6A, 0x01, 0x00, 0xff, 0xe6, 0x07, 0x03, 0x03, 0x10, 0x04, 0x00, 0x01};
        GByteArray *byteArray = g_byte_array_sized_new(sizeof(bytes));
        g_byte_array_append(byteArray, bytes, sizeof(bytes));
        binc_application_notify(application, service_uuid, char_uuid, byteArray);
        g_byte_array_free(byteArray, TRUE);
    }*/
}

void on_local_char_stop_notify(const Application *application, const char *service_uuid, const char *char_uuid) {
    HAPLogInfo(&logObject, "on stop notify");
}

gboolean on_request_authorization(Device *device) {
    HAPLogInfo(&logObject, "requesting authorization for '%s", binc_device_get_name(device));
    return TRUE;
}

guint32 on_request_passkey(Device *device) {
    guint32 pass = 000000;
    HAPLogInfo(&logObject, "requesting passkey for '%s", binc_device_get_name(device));
    HAPLogInfo(&logObject, "Enter 6 digit pin code: ");
    int result = fscanf(stdin, "%d", &pass);
    if (result != 1) {
        HAPLogInfo(&logObject, "didn't read a pin code");
    }
    return pass;
}


static void print_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;


	HAPLogInfo(&logObject, "%s%s", prefix, str);
}

void hexdump(const uint8_t* d, size_t len) {
  const char buffer[1024] = { 0 };
  char* buff_ptr = buffer;
  for (size_t i = 0; i < len ; i++) {
    int val = d[i];
    buff_ptr += snprintf(buff_ptr,(&buffer[1024] - buff_ptr), "0x%02x,", val);
  }
  HAPLogInfo(&logObject, "hdump %s", buffer);
}



void HAPPlatformBLEPeripheralManagerCreate(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        const HAPPlatformBLEPeripheralManagerOptions* options) {
    HAPPrecondition(blePeripheralManager);
    HAPPrecondition(options);
    HAPPrecondition(options->keyValueStore);

    if (blePeripheralManager->container == NULL) {
      blePeripheralManager->container = (OurBLEContainer*) malloc(sizeof(OurBLEContainer));
    }
    OurBLEContainer* c = blePeripheralManager->container;



    // Get a DBus connection
     c->dbusConnection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);

     // Setup handler for CTRL+C
     //if (signal(SIGINT, cleanup_handler) == SIG_ERR)
     //    log_error(TAG, "can't catch SIGINT");

     // Setup mainloop
     c->loop = g_main_loop_new(NULL, FALSE);

     // Get the default default_adapter
     c->default_adapter = binc_adapter_get_default(c->dbusConnection);

     // Set our default adapter.
     binc_adapter_set_user_data(c->default_adapter, &c);

     Adapter *default_adapter = c->default_adapter;

     if (default_adapter != NULL) {
         HAPLogInfo(&logObject, "using default_adapter '%s'", binc_adapter_get_path(default_adapter));

         // Make sure the adapter is on
         binc_adapter_set_powered_state_cb(default_adapter, &on_powered_state_changed);
         if (!binc_adapter_get_powered_state(default_adapter)) {
             binc_adapter_power_on(default_adapter);
         }

         // Register an agent and set callbacks
         c->agent = binc_agent_create(default_adapter, "/org/bluez/BincAgent", KEYBOARD_DISPLAY);
         binc_agent_set_request_authorization_cb(c->agent, &on_request_authorization);
         binc_agent_set_request_passkey_cb(c->agent, &on_request_passkey);

         // Setup remote central connection state callback
         binc_adapter_set_remote_central_cb(default_adapter, &on_central_state_changed);

         // Setup advertisement
         /*
         GPtrArray *adv_service_uuids = g_ptr_array_new();
         g_ptr_array_add(adv_service_uuids, HTS_SERVICE_UUID);

         c->advertisement = binc_advertisement_create();
         binc_advertisement_set_local_name(c->advertisement, "BINC");
         binc_advertisement_set_interval(c->advertisement, 500, 500);
         binc_advertisement_set_tx_power(c->advertisement, 5);
         binc_advertisement_set_services(c->advertisement, adv_service_uuids);
         g_ptr_array_free(adv_service_uuids, TRUE);
         binc_adapter_start_advertising(default_adapter, c->advertisement);
         */

         // Start application
         c->app = binc_create_application(default_adapter);
         /*
         binc_application_add_service(app, HTS_SERVICE_UUID);
         binc_application_add_characteristic(
                 app,
                 HTS_SERVICE_UUID,
                 TEMPERATURE_CHAR_UUID,
                 GATT_CHR_PROP_INDICATE | GATT_CHR_PROP_WRITE);
         binc_application_add_descriptor(
                 app,
                 HTS_SERVICE_UUID,
                 TEMPERATURE_CHAR_UUID,
                 CUD_CHAR,
                 GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE);

         const guint8 cud[] = "hello there";
         GByteArray *cudArray = g_byte_array_sized_new(sizeof(cud));
         g_byte_array_append(cudArray, cud, sizeof(cud));
         binc_application_set_desc_value(app, HTS_SERVICE_UUID, TEMPERATURE_CHAR_UUID, CUD_CHAR, cudArray);

         binc_application_set_char_read_cb(app, &on_local_char_read);
         binc_application_set_char_write_cb(app, &on_local_char_write);
         binc_application_set_char_start_notify_cb(app, &on_local_char_start_notify);
         binc_application_set_char_stop_notify_cb(app, &on_local_char_stop_notify);
         binc_application_set_char_updated_cb(app, &on_local_char_updated);
         */
         binc_adapter_register_application(default_adapter, c->app);


         c->loop = g_main_loop_new(NULL, FALSE);
         // Bail out after some time
         //g_timeout_add_seconds(600, callback, c);

         // Start the mainloop
         //g_main_loop_run(c->loop);
         struct LoopRunContext* ctx=  (struct LoopRunContext*) malloc(sizeof(struct LoopRunContext));

         // Create a new thread for the runner, we just never shut that down.
         ctx->main_loop = c->loop;
         ctx->main_context = g_main_loop_get_context(ctx->main_loop);

         pthread_t thread_id;
         pthread_create(&thread_id, NULL, &run_main_loop, ctx);


         // Clean up mainloop
         //g_main_loop_unref(c->loop);

         // Disconnect from DBus
         //g_dbus_connection_close_sync(c->dbusConnection, NULL, NULL);
         //g_object_unref(c->dbusConnection);
     } else {
         log_debug("MAIN", "No default_adapter found");
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

    OurBLEContainer* c = blePeripheralManager->container;
    HAPLog(&logObject, __func__);
    HAPLogInfo(&logObject, "advertising bytes: %u ", numAdvertisingBytes);

    hexdump(advertisingBytes, numAdvertisingBytes);

    // Data contains too much, so we need to trim the first 7 bytes...
    // 0x02,0x01,0x06,0x16,0xff,0x4c,0x00,    0x06,0x31
    //
    //
    int trim = 7;
    const uint8_t* actual_data = ((uint8_t*)advertisingBytes) + trim;
    numAdvertisingBytes = numAdvertisingBytes- trim;
    numAdvertisingBytes = 19;

    GByteArray* z = g_byte_array_new();
    g_byte_array_set_size(z, numAdvertisingBytes);
    memcpy(z->data, actual_data, numAdvertisingBytes);
    hexdump(actual_data, numAdvertisingBytes);
    HAPLogInfo(&logObject, "advertising bytes: %u ", numAdvertisingBytes);


    c->advertisement = binc_advertisement_create();
    binc_advertisement_set_general_discoverable(c->advertisement, true);

    uint16_t COMPANY_IDENTIFIER_CODE =  0x004c;
    binc_advertisement_set_manufacturer_data(c->advertisement,COMPANY_IDENTIFIER_CODE,z);
    g_byte_array_free(z, true);


    binc_adapter_start_advertising(c->default_adapter, c->advertisement);
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
