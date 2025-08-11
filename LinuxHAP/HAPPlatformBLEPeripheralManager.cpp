// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

#include <map>
#include <vector>
#include <string>
#include <memory>
#include <thread>
#include <sstream>
#include <iomanip>


#include "HAPLog.h"
#include "HAPPlatformBLEPeripheralManager+Init.h"
#include "HAPPlatformBLEPeripheralManager.h"
#include "HAPAssert.h"


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

#include "binc/adapter.h"
#include "binc/device.h"
#include "binc/application.h"
#include "binc/characteristic.h"

#include "binc/logger.h"
#include "binc/agent.h"
#include "binc/application.h"
#include "binc/advertisement.h"
#include "binc/utility.h"




// This seems to do what we want:
// https://github.com/bluez/bluez/blob/2c0c323d08357a4ff3065fcd49fee0c83b5835cd/tools/btgatt-server.c#L648
// But that uses internal??? api's?
// trying https://github.com/weliem/bluez_inc
//


// Context for the main loop service, this is pushed to the PAL loopback.
struct LoopRunContext{
  GMainLoop *main_loop;
  GMainContext *main_context;
};

void  run_main_loop(void* _Nullable context, size_t contextSize) {
  struct LoopRunContext* d = reinterpret_cast<LoopRunContext*>(context);
  g_main_context_iteration(d->main_context, FALSE);
}


static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "BLEPeripheralManager" };


std::string hexdump(const void* b, std::size_t length)
{
  const uint8_t* d = reinterpret_cast<const uint8_t*>(b);
  std::stringstream ss;
  for (std::size_t i = 0; i < length; i++)
  {
    ss << "" << std::setfill('0') << std::setw(2) << std::hex << int{ d[i] } << " ";
  }
  const auto z = ss.str();
  HAPLogInfo(&logObject, "hdump %s", z.c_str());
  return z;
}

/// Helper struct to create a string-based UUID.
struct RawUUID{
  char str[37] = { 0 };
  char pad{0}; // ensure the struct above has a zero termination.


  bool operator==(const RawUUID& other) const {
      return std::string(str) == std::string(other.str);
  }

  bool operator<(const RawUUID& other) const {
    return std::string(str) < std::string(other.str);
  }
  void load(const char* data) {
    memcpy(str, data, sizeof(str));
  }
  operator std::string() const {
    return std::string(str);
  }

 static RawUUID fromBytes(const uint8_t* uuid) {
    RawUUID res;
    snprintf(&res.str[0],sizeof(res.str),
    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[15], uuid[14], uuid[13], uuid[12], uuid[11], uuid[10], uuid[9], uuid[8],
        uuid[7], uuid[6], uuid[5], uuid[4], uuid[3], uuid[2], uuid[1], uuid[0]
    );
    return res;
  }
};

/// A characteristic is denoted by its uuid and the service uuid.
struct CharacteristicId {
  RawUUID service;
  RawUUID characteristic;

  bool operator==(const CharacteristicId& other) const {
      return std::make_pair(service, characteristic) == std::make_pair(other.service, other.characteristic);
  }

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

/// A descriptor is denoted by its uuid and the characteristic.
struct DescriptorId {
  CharacteristicId characteristic;
  RawUUID descriptor;


  bool operator==(const DescriptorId& other) const {
      return std::make_pair(characteristic, descriptor) == std::make_pair(other.characteristic, other.descriptor);
  }

  bool operator<(const DescriptorId& other) const {
    return std::make_pair(characteristic, descriptor) < std::make_pair(other.characteristic, other.descriptor);
  }

  static DescriptorId characteristic_descriptor(const CharacteristicId& characteristic_id, const char* descriptor_uuid) {
    DescriptorId res;
    res.characteristic = characteristic_id;
    res.descriptor.load(descriptor_uuid);
    return res;
  }

  operator std::string() const {
    return std::string(characteristic) + ":" + std::string(descriptor);
  }
};


struct OurBLEContainer {
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

  bool started_main_loop{false};
  bool registered_application{false};

  std::thread service_pusher;

  void service(){
    g_main_context_iteration(g_main_loop_get_context(loop), FALSE);
  }

  // There's an assert that checks if these handles and counters are zero.
  uint16_t handle_counter{1};
  uint16_t connection_handle{1};

  std::map<CharacteristicId, uint16_t> characteristic_handles;
  std::map<DescriptorId, uint16_t> descriptor_handles;

  HAPPlatformBLEPeripheralManagerDelegate delegate;
  HAPPlatformBLEPeripheralManagerRef manager;

};


void on_powered_state_changed(Adapter *adapter, gboolean state) {
  OurBLEContainer* c = reinterpret_cast<OurBLEContainer*>(binc_adapter_get_user_data(adapter));
  HAPLogInfo(&logObject, "powered '%s' (%s)", state ? "on" : "off", binc_adapter_get_path(adapter));
  HAPLogInfo(&logObject, "remote central %s is %s", binc_device_get_address(c->device),
  binc_device_get_connection_state_name(c->device));
}

/// Central state change, like connected/disconnected.
void on_central_state_changed(Adapter *adapter, Device *device) {
  OurBLEContainer* c = reinterpret_cast<OurBLEContainer*>(binc_adapter_get_user_data(adapter));


  if (c->device == NULL) {
    c->device = device;
  }

  char *deviceToString = binc_device_to_string(device);
  HAPLogInfo(&logObject,"%s\n", deviceToString);
  g_free(deviceToString);

  HAPLogInfo(&logObject, "remote central %s is %s", binc_device_get_address(device), binc_device_get_connection_state_name(device));

  ConnectionState state = binc_device_get_connection_state(device);
  if (state == BINC_CONNECTED) {
    c->connection_handle++;
    if (c->delegate.handleConnectedCentral) {
      (*(c->delegate.handleConnectedCentral))(c->manager, c->connection_handle, c->delegate.context);
    }
    binc_adapter_stop_advertising(c->default_adapter, c->advertisement);
  } else if (state == BINC_DISCONNECTED) {
    if (c->delegate.handleDisconnectedCentral) {
      (*(c->delegate.handleDisconnectedCentral))(c->manager, c->connection_handle, c->delegate.context);
    }
  }
}

// This function is called when a read is done
// Use this to set the characteristic value if it is not set or to reject the read request
const char *on_local_char_read(const Application *application, const char *address, const char *service_uuid,
                        const char *char_uuid) {
  OurBLEContainer* c = reinterpret_cast<OurBLEContainer*>(binc_application_get_user_data(application));


  CharacteristicId key = CharacteristicId::service_characteristic(service_uuid, char_uuid);
  std::string key_str = key;
  HAPLogError(&logObject, "Reading %s with %p", key_str.c_str(), c);

  const auto handle_it = c->characteristic_handles.find(key);
  HAPAssert(handle_it != c->characteristic_handles.end());

  const auto handle_id = handle_it->second;

  uint8_t bytes[kHAPPlatformBLEPeripheralManager_MaxAttributeBytes] = { 0 };
  size_t len = 0;

  HAPError err = c->delegate.handleReadRequest(
                      c->manager,
                      c->connection_handle,
                      handle_id,
                      bytes,
                      kHAPPlatformBLEPeripheralManager_MaxAttributeBytes,
                      &len,
                      c->delegate.context);
  HAPLogError(&logObject, "handleReadRequest returned %d, len is now: %zu", err, len);
  if (err != kHAPError_None ) {
    HAPAssert(err == kHAPError_InvalidState || err == kHAPError_OutOfResources);
    return BLUEZ_ERROR_REJECTED;
  }
  hexdump(bytes, len);

  // Okay, so now we have 'len' bytes in 'bytes' that we need to populate the characteristic with.
  GByteArray *byteArray = g_byte_array_sized_new(len);
  g_byte_array_append(byteArray, bytes, len);
  binc_application_set_char_value(application, service_uuid, char_uuid, byteArray);
  g_byte_array_free(byteArray, TRUE);

  return NULL;
}

// This function should be used to validate or reject a write request
const char *on_local_char_write(const Application *application, const char *address, const char *service_uuid,
                          const char *char_uuid, GByteArray *byteArray) {
  GString *result = g_byte_array_as_hex(byteArray);
  HAPLogError(&logObject, "write request characteristic <%s> with value <%s>", char_uuid, result->str);
  g_string_free(result, TRUE);

  OurBLEContainer* c = reinterpret_cast<OurBLEContainer*>(binc_application_get_user_data(application));

  CharacteristicId key = CharacteristicId::service_characteristic(service_uuid, char_uuid);
  std::string key_str = key;
  HAPLogError(&logObject, "Writing to  %s with %p", key_str.c_str(), c);

  const auto handle_it = c->characteristic_handles.find(key);
  HAPAssert(handle_it != c->characteristic_handles.end());

  const auto handle_id = handle_it->second;

  uint8_t bytes[kHAPPlatformBLEPeripheralManager_MaxAttributeBytes] = { 0 };
  size_t len = byteArray->len;
  // Copy from the gbyte array into our buffer.
  memcpy(bytes, byteArray->data, len);
  hexdump(byteArray->data, byteArray->len);

  // pass the buffer along.
  HAPError err = c->delegate.handleWriteRequest(
          c->manager,
          c->connection_handle,
          handle_id,
          bytes,
          len,
          c->delegate.context);
  HAPLogError(&logObject, "handleWriteRequest returned %d, len was: %zu", err, len);
  if (err) {
      HAPAssert(err == kHAPError_InvalidState || err == kHAPError_OutOfResources);
      return BLUEZ_ERROR_REJECTED;
  }
  // Nothing further to do.

  return NULL;
}

// This function is called after a write request was validates and the characteristic value was set
void on_local_char_updated(const Application *application, const char *service_uuid,
                           const char *char_uuid, GByteArray *byteArray) {
  GString *result = g_byte_array_as_hex(byteArray);
  HAPLogError(&logObject, "characteristic <%s> updated to <%s>", char_uuid, result->str);
  g_string_free(result, TRUE);
}

void on_local_char_start_notify(const Application *application, const char *service_uuid, const char *char_uuid) {
  HAPLogInfo(&logObject, "on start notify char %s, %s", service_uuid, char_uuid);
  OurBLEContainer* c = reinterpret_cast<OurBLEContainer*>(binc_application_get_user_data(application));
  binc_device_start_notify(c->device, service_uuid, char_uuid);
}

void on_local_char_stop_notify(const Application *application, const char *service_uuid, const char *char_uuid) {
  HAPLogInfo(&logObject, "on stop notify char %s, %s", service_uuid, char_uuid);
  OurBLEContainer* c = reinterpret_cast<OurBLEContainer*>(binc_application_get_user_data(application));
  binc_device_stop_notify(c->device, service_uuid, char_uuid);
}

gboolean on_request_authorization(Device *device) {
  HAPLogInfo(&logObject, "requesting authorization for '%s", binc_device_get_name(device));
  return TRUE;
}

guint32 on_request_passkey(Device *device) {
  HAPLogError(&logObject, "on_request_passkey");
  guint32 pass = 000000;
  HAPLogInfo(&logObject, "requesting passkey for '%s", binc_device_get_name(device));
  HAPLogInfo(&logObject, "Enter 6 digit pin code: ");
  int result = fscanf(stdin, "%d", &pass);
  if (result != 1) {
    HAPLogInfo(&logObject, "didn't read a pin code");
  }
  return pass;
}


// This callback is called just before the descriptor's value is returned.
// Use it to update the descriptor before it is read
const char* on_local_desc_read(const Application *application, const char *address,
                                          const char *service_uuid, const char *char_uuid, const char *desc_uuid){
  OurBLEContainer* c = reinterpret_cast<OurBLEContainer*>(binc_application_get_user_data(application));

  CharacteristicId char_key = CharacteristicId::service_characteristic(service_uuid, char_uuid);
  DescriptorId key = DescriptorId::characteristic_descriptor(char_key, desc_uuid);

  std::string key_str = key;
  HAPLogError(&logObject, "Reading %s", key_str.c_str(), c);

  const auto handle_it = c->descriptor_handles.find(key);
  HAPAssert(handle_it != c->descriptor_handles.end());

  const auto handle_id = handle_it->second;

  uint8_t bytes[kHAPPlatformBLEPeripheralManager_MaxAttributeBytes] = { 0 };
  size_t len = 0;

  HAPError err = c->delegate.handleReadRequest(
          c->manager,
          c->connection_handle,
          handle_id,
          bytes,
          kHAPPlatformBLEPeripheralManager_MaxAttributeBytes,
          &len,
          c->delegate.context);
  if (err) {
    HAPAssert(err == kHAPError_InvalidState || err == kHAPError_OutOfResources);
    return BLUEZ_ERROR_REJECTED;
  }
  hexdump(bytes, len);

  // Okay, so now we have 'len' bytes in 'bytes' that we need to populate the descriptor with.
  GByteArray *byteArray = g_byte_array_sized_new(len);
  g_byte_array_append(byteArray, bytes, len);
  binc_application_set_desc_value(application, service_uuid, char_uuid, desc_uuid, byteArray);
  g_byte_array_free(byteArray, TRUE);

  return NULL;
}

// This callback is called just before the descriptor's value is set.
// Use it to accept (return NULL), or reject (return BLUEZ_ERROR_*) the byte array
const char *on_local_desc_write(const Application *application, const char *address,
                                            const char *service_uuid, const char *char_uuid,
                                            const char *desc_uuid, const GByteArray *byteArray){

  GString *result = g_byte_array_as_hex(byteArray);
  HAPLogError(&logObject, "write request characteristic <%s> with value <%s>", char_uuid, result->str);
  g_string_free(result, TRUE);

  OurBLEContainer* c = reinterpret_cast<OurBLEContainer*>(binc_application_get_user_data(application));

  CharacteristicId char_key = CharacteristicId::service_characteristic(service_uuid, char_uuid);
  DescriptorId key = DescriptorId::characteristic_descriptor(char_key, desc_uuid);

  std::string key_str = key;
  HAPLogError(&logObject, "Writing to desc  %s with %p", key_str.c_str(), c);
  hexdump(byteArray->data, byteArray->len);

  const auto handle_it = c->descriptor_handles.find(key);
  HAPAssert(handle_it != c->descriptor_handles.end());

  const auto handle_id = handle_it->second;

  uint8_t bytes[kHAPPlatformBLEPeripheralManager_MaxAttributeBytes] = { 0 };
  size_t len = byteArray->len;
  // Copy from the gbyte array into our buffer.
  memcpy(bytes, byteArray->data, len);

  HAPError err = c->delegate.handleWriteRequest(
          c->manager,
          c->connection_handle,
          handle_id,
          bytes,
          len,
          c->delegate.context);
  if (err) {
    HAPAssert(err == kHAPError_InvalidState || err == kHAPError_OutOfResources);
    return BLUEZ_ERROR_REJECTED;
  } else {
    return NULL;
  }

  // Nothing to do here.
  return NULL;
}



static void print_debug(const char *str, void *user_data)
{
  const char *prefix = reinterpret_cast<const char*>(str);
  HAPLogInfo(&logObject, "%s%s", prefix, str);
}


void HAPPlatformBLEPeripheralManagerCreate(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        const HAPPlatformBLEPeripheralManagerOptions* options) {
  HAPPrecondition(blePeripheralManager);
  HAPPrecondition(options);
  HAPPrecondition(options->keyValueStore);

  if (blePeripheralManager->container == NULL) {
    blePeripheralManager->container = std::make_unique<OurBLEContainer>().release();
  }
  OurBLEContainer* c = blePeripheralManager->container;

  c->manager = blePeripheralManager;


  // Get a DBus connection
  c->dbusConnection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);

  // Setup mainloop
  c->loop = g_main_loop_new(NULL, FALSE);

  // Get the default default_adapter
  c->default_adapter = binc_adapter_get_default(c->dbusConnection);

  // Set our default adapter.
  binc_adapter_set_user_data(c->default_adapter, c);

  Adapter *default_adapter = c->default_adapter;

  if (default_adapter != NULL) {
    HAPLogInfo(&logObject, "using default_adapter '%s'", binc_adapter_get_path(default_adapter));

    binc_adapter_pairable_off(c->default_adapter);
    binc_adapter_discoverable_on(c->default_adapter);

    // Make sure the adapter is on
    binc_adapter_set_powered_state_cb(default_adapter, &on_powered_state_changed);
    if (!binc_adapter_get_powered_state(default_adapter)) {
        binc_adapter_power_on(default_adapter);
    }

    // Register an agent and set callbacks
    c->agent = binc_agent_create(default_adapter, "/org/bluez/BincAgent", KEYBOARD_DISPLAY);

    // Authorization/passkey isn't used.
    //binc_agent_set_request_authorization_cb(c->agent, &on_request_authorization);
    //binc_agent_set_request_passkey_cb(c->agent, &on_request_passkey);

    // Setup remote central connection state callback
    binc_adapter_set_remote_central_cb(default_adapter, &on_central_state_changed);

    // Start application
    c->app = binc_create_application(default_adapter);
    binc_application_set_user_data(c->app, c);

    // Setup characteristic callbacks.
    binc_application_set_char_read_cb(c->app, &on_local_char_read);
    binc_application_set_char_write_cb(c->app, &on_local_char_write);
    binc_application_set_char_start_notify_cb(c->app, &on_local_char_start_notify);
    binc_application_set_char_stop_notify_cb(c->app, &on_local_char_stop_notify);
    binc_application_set_char_updated_cb(c->app, &on_local_char_updated);

    // Setup descriptor callbacks.
    binc_application_set_desc_read_cb(c->app, on_local_desc_read);
    binc_application_set_desc_write_cb(c->app, on_local_desc_write);


    // Skip cleanup, the OS is the garbage collector.
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

  OurBLEContainer* c = blePeripheralManager_->container;
  if (delegate_) {
    c->delegate = *delegate_;
  }

  HAPLog(&logObject, __func__);
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

  HAPLog(&logObject, __func__);

  HAPLogError(&logObject, "Can't set device name");
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


  // We cannot handle non primary services, so drop the ball if they are not primary.
  HAPAssert(isPrimary);

  RawUUID b = RawUUID::fromBytes(type->bytes);
  c->recent_service = b;
  hexdump(type->bytes, 16);
  HAPLogInfo(&logObject, "l: %d ", __LINE__);
  int res = binc_application_add_service(c->app, b.str);
  HAPLogInfo(&logObject, "l: %d ", __LINE__);
  HAPAssert(res == 0);

  //c->service();
  return kHAPError_None;
}

void HAPPlatformBLEPeripheralManagerRemoveAllServices(HAPPlatformBLEPeripheralManagerRef blePeripheralManager) {
  HAPPrecondition(blePeripheralManager);

  HAPLog(&logObject, __func__);

  //  [peripheral removeAllServices];
}

std::string to_string(HAPPlatformBLEPeripheralManagerCharacteristicProperties properties){
  std::string prop;
  if (properties.read)
      prop += "PROP_READ";
  if (properties.write)
    prop += " PROP_WRITE";
  if (properties.writeWithoutResponse)
    prop += " PROP_WRITE_WITHOUT_RESP";
  if (properties.notify)
    prop += " PROP_NOTIFY";
  if (properties.indicate)
    prop += " PROP_INDICATE";

  return prop;
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
static guint makePermissionDescr(HAPPlatformBLEPeripheralManagerDescriptorProperties properties) {
  guint prop = 0;

  if (properties.read)
      prop |= GATT_CHR_PROP_READ;
  if (properties.write)
      prop |= GATT_CHR_PROP_WRITE;


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

  std::string behaviour = to_string(properties);
  HAPLogInfo(&logObject, "add characteristic, const bytes: %lu  behaviour: %s", constNumBytes, behaviour.c_str());
  hexdump(type->bytes, 16);


  RawUUID b = RawUUID::fromBytes(type->bytes);
  c->recent_characteristic = b;
  guint permissions = makePermission(properties);
  int res = binc_application_add_characteristic(c->app, recent_service,
                                          b.str, permissions);
  HAPAssert(res == 0);
  CharacteristicId key;
  key.service = c->recent_service;
  key.characteristic = b;
  if (constNumBytes != 0) {
    HAPLogError(&logObject, "Have const data that needs handling.");
    std::vector<uint8_t> data;
    data.resize(constNumBytes);
    memcpy(data.data(), constBytes, constNumBytes);
    c->characteristic_values[key] = data;
  }

  // Good enough for now?
  c->handle_counter++;
  c->characteristic_handles[key] = c->handle_counter;
  *valueHandle = c->handle_counter;
  if (properties.notify || properties.indicate) {
    *cccDescriptorHandle = c->handle_counter;
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

  HAPLogInfo(&logObject, "add characteristic, const bytes: %zu ", constNumBytes);
  hexdump(type->bytes, 16);

  RawUUID b = RawUUID::fromBytes(type->bytes);
  guint permissions = makePermissionDescr(properties);

  CharacteristicId char_key;
  char_key.service = c->recent_service;
  char_key.characteristic = c->recent_characteristic;
  DescriptorId key = DescriptorId::characteristic_descriptor(char_key, b.str);

  int res = binc_application_add_descriptor(
          c->app,
          recent_service,
          recent_characteristic,
          b.str,
          permissions);
  HAPAssert(res == 0);

  if (constNumBytes != 0) {
    HAPLogInfo(&logObject, "Setting const data for descriptor: %s", std::string(b).c_str());
    hexdump(constBytes, constNumBytes);
    GByteArray *cudArray = g_byte_array_sized_new(constNumBytes);
    g_byte_array_append(cudArray, reinterpret_cast<const unsigned char*>(constBytes), constNumBytes);
    res = binc_application_set_desc_value(c->app,
      recent_service,
      recent_characteristic,
      b.str, cudArray);
    HAPAssert(res == 0);
    g_byte_array_free(cudArray, true);
  }

  // Good enough for now?
  c->handle_counter++;
  c->descriptor_handles[key] = c->handle_counter;
  *descriptorHandle = c->handle_counter;

  return kHAPError_None;
}

void HAPPlatformBLEPeripheralManagerPublishServices(HAPPlatformBLEPeripheralManagerRef blePeripheralManager) {
  HAPPrecondition(blePeripheralManager);

  OurBLEContainer* c = blePeripheralManager->container;
  HAPLog(&logObject, __func__);

  // We're ready to roll, so lets start the application.
  if (!c->registered_application){
    binc_adapter_register_application(c->default_adapter, c->app);
    c->registered_application = true;
  }

  // Lets also start a background thread to push the event loop service onto the HAP service loop.
  if (!c->started_main_loop) {
    LoopRunContext ctx;
    ctx.main_loop = 0;
    ctx.main_context = g_main_loop_get_context(c->loop);
    c->service_pusher = std::thread([ctx](){
      while (true) {
        LoopRunContext copied = ctx;
        int r = HAPPlatformRunLoopScheduleCallback(run_main_loop, &copied, sizeof(ctx));
        HAPAssert(r == kHAPError_None);
        usleep(10000);
      }
    });
    c->started_main_loop = true;
  }

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
  HAPLogInfo(&logObject, "advertising bytes: %zu ", numAdvertisingBytes);

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
  HAPLogInfo(&logObject, "advertising bytes: %zu ", numAdvertisingBytes);

  c->advertisement = binc_advertisement_create();
  binc_advertisement_set_general_discoverable(c->advertisement, true);

  binc_advertisement_set_local_name(c->advertisement, "BINC");
  uint16_t COMPANY_IDENTIFIER_CODE =  0x004c;
  binc_advertisement_set_manufacturer_data(c->advertisement,COMPANY_IDENTIFIER_CODE,z);
  g_byte_array_free(z, true);

  int before = binc_adapter_is_pairable(c->default_adapter);
  //HAPLogFault(&logObject, "pairable before %d", before);

  binc_adapter_pairable_off(c->default_adapter);
  c->service();
  binc_adapter_start_advertising(c->default_adapter, c->advertisement);
  c->service();
  before = binc_adapter_is_pairable(c->default_adapter);
  //HAPLogFault(&logObject, "pairable before %d", before);
}

void HAPPlatformBLEPeripheralManagerStopAdvertising(HAPPlatformBLEPeripheralManagerRef blePeripheralManager) {
  HAPPrecondition(blePeripheralManager);

  OurBLEContainer* c = blePeripheralManager->container;
  HAPPrecondition(c->default_adapter);
  HAPPrecondition(c->advertisement);
  HAPLog(&logObject, __func__);

  binc_adapter_stop_advertising(c->default_adapter, c->advertisement);
  // This here causes a bad free? Why is that? Do we have to service the main loop before doing this?
  //binc_advertisement_free(c->advertisement);
}

void HAPPlatformBLEPeripheralManagerCancelCentralConnection(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        HAPPlatformBLEPeripheralManagerConnectionHandle connectionHandle HAP_UNUSED) {
  HAPPrecondition(blePeripheralManager);
  HAPLog(&logObject, __func__);

  // Request a disconnect.
  OurBLEContainer* c = blePeripheralManager->container;
  binc_device_disconnect(c->device);
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
