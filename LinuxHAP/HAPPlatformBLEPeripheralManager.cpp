// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

#include <map>
#include <vector>
#include <string>
#include <memory>
#ifdef __cplusplus
extern "C" {
#endif

//#include "HAPAssert.h"
#include "HAPLog.h"
#include "HAPPlatformBLEPeripheralManager+Init.h"

#include <math.h>
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
//#include "binc/device_internal.h"
#include "binc/logger.h"
#include "binc/agent.h"
#include "binc/application.h"
#include "binc/advertisement.h"
#include "binc/utility.h"
#include "binc/parser.h"

// Use the raw HCI interface
// https://github.com/embassy-rs/trouble/blob/main/examples/linux/src/lib.rs
// https://github.com/bluez/bluez/wiki/HCI

// https://github.com/bluez/bluez/blob/2c0c323d08357a4ff3065fcd49fee0c83b5835cd/unit/test-gatt.c#L675

// https://github.com/bluez/bluez/blob/2c0c323d08357a4ff3065fcd49fee0c83b5835cd/tools/btgatt-server.c#L648
//


// trying https://github.com/weliem/bluez_inc
//
// No use data on the application.



static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "BLEPeripheralManager" };

struct LoopRunContext{
  GMainLoop *main_loop;
  GMainContext *main_context;
};

void* run_main_loop(void *data) {
    struct LoopRunContext* d = reinterpret_cast<LoopRunContext*>(data);
    g_main_context_push_thread_default(d->main_context);
    g_main_loop_run(d->main_loop);
    g_main_context_pop_thread_default(d->main_context);
    return nullptr;
}

struct RawUUID{
  char str[37] = { 0 };
  char pad{0};


  bool operator==(const RawUUID& other) const {
      return std::string(str) == std::string(other.str);
  }

  // Overload the less than operator (<)
  bool operator<(const RawUUID& other) const {
    return std::string(str) < std::string(other.str);
  }
  void load(const char* data) {
    memcpy(str, data, sizeof(str));
  }
  operator std::string() const {
    return std::string(str);
  }
};

struct CharacteristicId {
  RawUUID service;
  RawUUID characteristic;

  // Overload the equality operator (==)
  bool operator==(const CharacteristicId& other) const {
      return std::make_pair(service, characteristic) == std::make_pair(other.service, other.characteristic);
  }

  // Overload the less than operator (<)
  bool operator<(const CharacteristicId& other) const {
    return std::make_pair(service, characteristic) < std::make_pair(other.service, other.characteristic);

  }
  static CharacteristicId service_characteristic(const char* service_uuid, const char* char_uuid) {
    CharacteristicId res;
    res.service.load(service_uuid);
    res.characteristic.load(char_uuid);
    return res;
  }
  operator std::string() const {
    return std::string(service) + ":" + std::string(characteristic);
  }
};


typedef struct OurBLEContainer {


  GDBusConnection * dbusConnection{nullptr};
  GMainLoop *loop{nullptr};
  Adapter *default_adapter{nullptr};
  Advertisement *advertisement{nullptr};
  Application *app{nullptr};
  Agent *agent{nullptr};
  Device * device{nullptr};
  RawUUID recent_service;
  RawUUID recent_characteristic;

  std::map<CharacteristicId, std::vector<uint8_t>> characteristic_values;

} OurBLEContainer;

static OurBLEContainer* container_singleton = nullptr;

void on_powered_state_changed(Adapter *adapter, gboolean state) {
    OurBLEContainer* c = reinterpret_cast<OurBLEContainer*>(binc_adapter_get_user_data(adapter));
    HAPLogInfo(&logObject, "powered '%s' (%s)", state ? "on" : "off", binc_adapter_get_path(adapter));
    // HAPLogInfo(&logObject, "%s%s", prefix, str);
}

void on_central_state_changed(Adapter *adapter, Device *device) {
  OurBLEContainer* c = reinterpret_cast<OurBLEContainer*>(binc_adapter_get_user_data(adapter));

    if (c->device == NULL) {
      c->device = device;
    }

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
    OurBLEContainer* c = container_singleton;


    CharacteristicId key = CharacteristicId::service_characteristic(service_uuid, char_uuid);
    std::string key_str = key;
    HAPLogInfo(&logObject, "Reading %s", key_str.c_str());


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
	const char *prefix = reinterpret_cast<const char*>(str);


	HAPLogInfo(&logObject, "%s%s", prefix, str);
}

void hexdump(const void* b, size_t len) {
  const uint8_t* d = reinterpret_cast<const uint8_t*>(b);
  char buffer[1024] = { 0 };
  char* buff_ptr = buffer;
  for (size_t i = 0; i < len ; i++) {
    int val = d[i];
    buff_ptr += snprintf(buff_ptr,(&buffer[1024] - buff_ptr), "0x%02x,", val);
  }
  HAPLogInfo(&logObject, "hdump %s", buffer);
}

static struct RawUUID fromBytes(const uint8_t* uuid) {
  RawUUID res;
  snprintf(&res.str[0],sizeof(res.str),
  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
      uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
  );
  return res;
}


void HAPPlatformBLEPeripheralManagerCreate(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        const HAPPlatformBLEPeripheralManagerOptions* options) {
    HAPPrecondition(blePeripheralManager);
    HAPPrecondition(options);
    HAPPrecondition(options->keyValueStore);

    if (blePeripheralManager->container == NULL) {
      blePeripheralManager->container = std::make_unique<OurBLEContainer>().release();
      container_singleton = blePeripheralManager->container;
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
         //binc_application_set_char_value(const Application *application, const char *service_uuid, const char *char_uuid, GByteArray *byteArray)
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

         */
         binc_application_set_char_read_cb(c->app, &on_local_char_read);
         binc_application_set_char_write_cb(c->app, &on_local_char_write);
         binc_application_set_char_start_notify_cb(c->app, &on_local_char_start_notify);
         binc_application_set_char_stop_notify_cb(c->app, &on_local_char_stop_notify);
         binc_application_set_char_updated_cb(c->app, &on_local_char_updated);

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
         pthread_create(&thread_id, NULL, run_main_loop, ctx);


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


static void inject_hex(uint8_t* location, uint8_t v) {
    const char* lookup = "0123456789ABCDEF";
    uint8_t low = v& 0xf;
    uint8_t high =  (v >> 4) & 0xF;
    location[0] = lookup[high];
    location[1] = lookup[low];
}

void HAPPlatformBLEPeripheralManagerSetDeviceAddress(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        const HAPPlatformBLEPeripheralManagerDeviceAddress* deviceAddress) {
    HAPPrecondition(blePeripheralManager);
    HAPPrecondition(deviceAddress);

    HAPLog(&logObject, __func__);

    hexdump(deviceAddress, 6);

    uint8_t address_with_colons[sizeof("AA:BB:CC:DD:EE:FF") ] = "AA:BB:CC:DD:EE:FF";
    for (uint8_t bindex = 0; bindex < 6; bindex++){
      const uint8_t* rawbytes = (const uint8_t*)deviceAddress;
      inject_hex(&(address_with_colons[bindex * 3]), rawbytes[bindex]);
    }
    hexdump(address_with_colons, sizeof("AA:BB:CC:DD:EE:FF") );

    HAPLogInfo(&logObject, "Setting address to  to %s", address_with_colons);
    OurBLEContainer* c = blePeripheralManager->container;
    //HAPPrecondition(c->device);

    HAPLogError(&logObject, "much sad, can't set address");
    //binc_device_set_address(c->device, address_with_colons);
}

void HAPPlatformBLEPeripheralManagerSetDeviceName(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        const char* deviceName) {
    HAPPrecondition(blePeripheralManager);
    HAPPrecondition(deviceName);

    HAPLogInfo(&logObject, "Setting name to %s", deviceName);
    OurBLEContainer* c = blePeripheralManager->container;
    //binc_device_set_name(c->device, deviceName);

    HAPLog(&logObject, __func__);

    HAPLogError(&logObject, "Can't set device name");
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

    OurBLEContainer* c = blePeripheralManager->container;

    struct RawUUID b = fromBytes((uint8_t*)type);
    c->recent_service = b;
    hexdump(type->bytes, 16);
    int res = binc_application_add_service(c->app, b.str);
    HAPAssert(res == 0);

    return kHAPError_None;
}

void HAPPlatformBLEPeripheralManagerRemoveAllServices(HAPPlatformBLEPeripheralManagerRef blePeripheralManager) {
    HAPPrecondition(blePeripheralManager);

    HAPLog(&logObject, __func__);

    //  [peripheral removeAllServices];
}

static guint makePermission(HAPPlatformBLEPeripheralManagerCharacteristicProperties properties) {
  guint prop = 0;

  if (properties.read)
      prop |= GATT_CHR_PROP_READ;
  if (properties.write)
      prop |= GATT_CHR_PROP_WRITE;
  if (properties.writeWithoutResponse)
      prop |= GATT_CHR_PROP_WRITE_WITHOUT_RESP;
  if (properties.notify)
      prop |= GATT_CHR_PROP_NOTIFY;
  if (properties.indicate)
      prop |= GATT_CHR_PROP_INDICATE;

  return prop;
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
    OurBLEContainer* c = blePeripheralManager->container;

    const char* recent_service = c->recent_service.str;

    HAPLogInfo(&logObject, "add characteristic, const bytes: %lu ", constNumBytes);
    hexdump(type->bytes, 16);


    struct RawUUID b = fromBytes((uint8_t*)type);
    c->recent_characteristic = b;
    guint permissions = makePermission(properties);
    int res = binc_application_add_characteristic(c->app, recent_service,
                                            b.str, permissions);
    if (constNumBytes != 0) {
      HAPLogError(&logObject, "Have const data that needs handling.");
      CharacteristicId key;
      key.service = c->recent_service;
      key.characteristic = b;
      std::vector<uint8_t> data;
      data.resize(constNumBytes);
      memcpy(data.data(), constBytes, constNumBytes);
      c->characteristic_values[key] = data;

    }

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


    OurBLEContainer* c = blePeripheralManager->container;

    const char* recent_service = c->recent_service.str;
    const char* recent_characteristic = c->recent_characteristic.str;

    HAPLogInfo(&logObject, "add characteristic, const bytes: %lu ", constNumBytes);
    hexdump(type->bytes, 16);


    struct RawUUID b = fromBytes((uint8_t*)type);
    //guint permissions = makePermission(properties);


    binc_application_add_descriptor(
            c->app,
            recent_service,
            recent_characteristic,
            b.str,
            GATT_CHR_PROP_READ | GATT_CHR_PROP_WRITE);

    if (constNumBytes != 0) {
      HAPLogInfo(&logObject, "Setting const data for descriptor: %s", std::string(b).c_str());
      hexdump(constBytes, constNumBytes);
      GByteArray *cudArray = g_byte_array_sized_new(constNumBytes);
      g_byte_array_append(cudArray, reinterpret_cast<const unsigned char*>(constBytes), constNumBytes);
      binc_application_set_desc_value(c->app,
        recent_service,
        recent_characteristic,
        b.str, cudArray);
      g_byte_array_free(cudArray, true);
    }


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
    numAdvertisingBytes = 19; // and just truncate the rear.

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

    OurBLEContainer* c = blePeripheralManager->container;
    HAPPrecondition(c->default_adapter);
    HAPPrecondition(c->advertisement);
    HAPLog(&logObject, __func__);

    binc_adapter_stop_advertising(c->default_adapter, c->advertisement);
    binc_advertisement_free(c->advertisement);

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

#ifdef __cplusplus
}
#endif
