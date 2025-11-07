#pragma once


#include <map>
#include <vector>
#include <string>
#include <cstring>
#include <memory>
#include <thread>
#include <sstream>
#include <iomanip>

#include <pthread.h>
#include <stdio.h>

#include "HAPLog.h"
#include "HAPPlatformBLEPeripheralManager+Init.h"
#include "HAPPlatformBLEPeripheralManager.h"
#include "HAPAssert.h"
#include "HAPPlatformLinuxShared.h"

#include "binc/forward_decl.h"


static const HAPLogObject logObjectBleLinuxShared = { .subsystem = kHAPPlatform_LogSubsystem, .category = "BLELinuxShared" };

std::string hexdump(const void* b, std::size_t length)
{
  const uint8_t* d = reinterpret_cast<const uint8_t*>(b);
  std::stringstream ss;
  for (std::size_t i = 0; i < length; i++)
  {
    ss << "0x" << std::setfill('0') << std::setw(2) << std::hex << int{ d[i] } << ", ";
  }
  const auto z = ss.str();
  HAPLogInfo(&logObjectBleLinuxShared, "hdump %s", z.c_str());
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
    std::memcpy(str, data, sizeof(str));
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

  void service();

  // There's an assert that checks if these handles and counters are zero.
  uint16_t handle_counter{1};
  uint16_t connection_handle{1};

  std::map<CharacteristicId, uint16_t> characteristic_handles;
  std::map<DescriptorId, uint16_t> descriptor_handles;

  HAPPlatformBLEPeripheralManagerDelegate delegate;
  HAPPlatformBLEPeripheralManagerRef manager;

};


inline void inject_hex(uint8_t* location, uint8_t v) {
  const char* lookup = "0123456789ABCDEF";
  uint8_t low = v& 0xf;
  uint8_t high =  (v >> 4) & 0xF;
  location[0] = lookup[high];
  location[1] = lookup[low];
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
