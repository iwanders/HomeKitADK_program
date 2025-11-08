

#include <map>
#include <unistd.h>
#include <vector>
#include <string>
#include <memory>
#include <thread>
#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <deque>
#include <filesystem>

#include "HAPLog.h"
#include "HAPPlatformBLEPeripheralManager+Init.h"
#include "HAPPlatformBLEPeripheralManager.h"
#include "HAPAssert.h"

struct GDBusConnection;
struct GMainLoop;

#include "HAPPlatformLinuxShared.h"

using Bytes = std::vector<std::uint8_t>;

static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "BLEPeripheralManager" };

static OurBLEContainer* our_container = nullptr;

Bytes on_local_char_read(const OurBLEContainer* c, const char *address, const char *service_uuid,
                        const char *char_uuid);
bool on_local_char_write(const OurBLEContainer* c, const char *address, const char *service_uuid,
                          const char *char_uuid, Bytes byteArray);

// Random bytes is consumed from the left side, we can append to it.
static std::deque<std::uint8_t> random_bytes;

void writeSaltAndVerifier(const Bytes& salt, const Bytes& verifier);
std::string hexdump(const Bytes& bytes)
{
  const auto b = bytes.data();
  const auto length = bytes.size();
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

void test_message_exchange(OurBLEContainer* c);

void  run_main_loop(void* _Nullable context, size_t contextSize) {
  // THis is a pointer to a pointer.
  OurBLEContainer* c = *reinterpret_cast<OurBLEContainer**>(context);
  std::cout << "Doing c->delegate.handleConnectedCentral " << c->delegate.handleConnectedCentral << std::endl;
  std::cout << "Doing c->manager " << c->manager << std::endl;

  if (c->delegate.handleConnectedCentral && c->manager) {
    std::cout << "cc things" << std::endl;

    c->connection_handle++;
    (*(c->delegate.handleConnectedCentral))(c->manager, c->connection_handle, c->delegate.context);
    test_message_exchange(c); // never returns.
  }
  usleep(100);

  int r = HAPPlatformRunLoopScheduleCallback(run_main_loop, &c,sizeof(void*));
  HAPAssert(r == kHAPError_None);
}


// Do a global initialisation trick to get an execution in before any of the other HAP code gets cycles.
// This allows us to switch to a temporary directory for a fresh run. Where we can make a nice mess out of the
// kv store =)
struct TestMessageExchangeConstructorTrick{
  TestMessageExchangeConstructorTrick() {
    std::cout << " I run early " << std::endl;

    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm now_tm = *std::localtime(&now_c);
    std::stringstream ss;
    ss << std::put_time(&now_tm, "%Y-%m-%d_%H-%M-%S");
    std::string directory_name = ss.str();

    std::filesystem::path base_dir_path = "/tmp/hap_test/";
    std::filesystem::create_directory(base_dir_path);
    std::filesystem::path dir_path =base_dir_path / ("test_" + directory_name );

    std::filesystem::create_directory(dir_path);

    // Change the directory to that new directory.
    std::filesystem::current_path(dir_path);

    // And then symlink that .HomeKitStore dir that the it wants into the directory
    // such that we can look at the files easily and write them without subpaths.
    std::filesystem::path store_path = dir_path / ".HomeKitStore";
    std::filesystem::create_symlink(dir_path, store_path);
  }
};
static TestMessageExchangeConstructorTrick z;

void test_message_exchange(OurBLEContainer* c){
    struct FakeWrite{
      const char* service_uuid;
      const char* char_uuid;
      std::vector<std::uint8_t> payload;
    };

    const auto proto_srv = "000000a2-0000-1000-8000-0026bb765291";
    const auto proto_service_sig_chr = "000000a5-0000-1000-8000-0026bb765291";
    const auto pairing_srv = "00000055-0000-1000-8000-0026bb765291";
    const auto pairing_srv_pair_setup_chr = "0000004c-0000-1000-8000-0026bb765291";
    const auto bulb_srv = "00000043-0000-1000-8000-0026bb765291";
    const auto bulb_srv_on_chr = "00000025-0000-1000-8000-0026bb765291";


    writeSaltAndVerifier({0x3d, 0xc2, 0x81, 0xab, 0x08, 0xed, 0x4d, 0x8c, 0x52, 0x0c, 0xb2, 0x5f, 0xc2, 0x51, 0x9c,
    0x1f},{0xe3, 0x7e, 0xa0, 0xd4, 0x45, 0xab, 0x91, 0xcc, 0xee, 0x92, 0x33, 0x20, 0x9e, 0xb3, 0x8f,
    0xfc, 0xd7, 0x04, 0x20, 0xd1, 0x95, 0x34, 0x73, 0x5a, 0x17, 0x2e, 0xca, 0xef, 0xe3, 0x8d,
    0x1a, 0x21, 0xfb, 0x5e, 0x2d, 0x18, 0x1b, 0xb0, 0x80, 0x77, 0x12, 0xf7, 0x2d, 0x2e, 0x64,
    0x67, 0xc7, 0xa8, 0xb5, 0xc0, 0xe3, 0xab, 0xe4, 0x60, 0x58, 0x9f, 0xde, 0x39, 0x62, 0xdc,
    0x70, 0x01, 0x42, 0x1a, 0x07, 0x47, 0x16, 0x63, 0xf7, 0xd7, 0xee, 0x9b, 0xf9, 0x7b, 0x35,
    0xc4, 0x3b, 0x5d, 0x0a, 0xd6, 0x07, 0xdb, 0x47, 0x84, 0x05, 0x22, 0x9b, 0xc8, 0x0f, 0xb3,
    0xb4, 0x39, 0xc7, 0x18, 0xc9, 0xb0, 0x85, 0x8d, 0x19, 0xf5, 0x56, 0xc6, 0xee, 0x9b, 0xd8,
    0x87, 0x8a, 0x39, 0xf9, 0x21, 0x35, 0xaa, 0x42, 0x50, 0x6d, 0xa3, 0x5a, 0x3f, 0x67, 0x55,
    0x6a, 0x5c, 0x6c, 0x92, 0x07, 0x44, 0xd3, 0xd6, 0x97, 0x6b, 0x5a, 0x5c, 0xcf, 0x6b, 0xdf,
    0xf5, 0x1d, 0x4c, 0xde, 0x3f, 0x2d, 0xf7, 0x95, 0x3c, 0x70, 0xde, 0x65, 0xcf, 0x22, 0x96,
    0xe8, 0x12, 0x8f, 0xa7, 0x9a, 0xa7, 0x68, 0xfe, 0x00, 0x18, 0x7f, 0x6d, 0xed, 0x98, 0xc9,
    0x6b, 0xfc, 0xd2, 0x9b, 0xa9, 0x08, 0x93, 0x3e, 0x3e, 0x7f, 0x7c, 0x63, 0x03, 0x49, 0xdf,
    0x52, 0x18, 0xcf, 0x9f, 0xf3, 0xbb, 0x11, 0xb5, 0xa3, 0x05, 0x03, 0x6b, 0xba, 0xf8, 0x91,
    0x60, 0xc2, 0xf1, 0x1e, 0x5f, 0x0c, 0x81, 0x08, 0x25, 0xda, 0xed, 0xef, 0xa0, 0xfe, 0x73,
    0xbf, 0xd8, 0xe3, 0xdb, 0xdc, 0xf6, 0x54, 0x42, 0x9a, 0xea, 0xf2, 0x69, 0x46, 0x14, 0x0c,
    0x86, 0x97, 0x56, 0x95, 0x8b, 0x5b, 0x1f, 0x87, 0x99, 0x5c, 0xaf, 0x6a, 0xf4, 0xe5, 0x66,
    0xe9, 0xf9, 0x7b, 0xa5, 0x1f, 0xf8, 0x8e, 0xa7, 0x81, 0xcc, 0x4e, 0xdd, 0x20, 0x94, 0x2d,
    0x31, 0x78, 0xb6, 0x26, 0xf6, 0x41, 0x07, 0xa7, 0xad, 0x97, 0x18, 0xff, 0x7a, 0x0f, 0x3c,
    0x55, 0x4b, 0xc3, 0x4d, 0x58, 0xc9, 0x56, 0xed, 0x6b, 0x69, 0xc4, 0x56, 0xf4, 0xf0, 0x5f,
    0x58, 0x7f, 0x98, 0xfa, 0x4a, 0xf7, 0x8e, 0xda, 0x49, 0xc8, 0x69, 0x88, 0xae, 0x9c, 0x39,
    0x1f, 0xa2, 0xc4, 0x58, 0x78, 0x35, 0xba, 0x73, 0x01, 0xae, 0xa2, 0xa9, 0x4d, 0x90, 0xf3,
    0x98, 0x14, 0xb9, 0x6f, 0x4f, 0x21, 0x01, 0xdd, 0xad, 0x1a, 0x52, 0x45, 0x13, 0xe9, 0x08,
    0xb0, 0x89, 0x54, 0xee, 0xe3, 0x44, 0x08, 0xd4, 0x77, 0x4b, 0xab, 0x65, 0x6e, 0xba, 0xec,
    0xf9, 0xce, 0x9d, 0x5f, 0xd5, 0x4a, 0xde, 0xdf, 0x8f, 0x67, 0x47, 0x65, 0xe2, 0x2f, 0x8f,
    0x9f, 0x53, 0xab, 0x56, 0xb1, 0x22, 0x6c, 0xe3, 0x5c, 0x8e, 0x97, 0x2f, 0x9f, 0x82, 0xf1,
    0xd2, 0x11, 0x2f, 0x1a, 0xc3, 0x2a, 0x60, 0x28, 0x83});

    //  FakeWrite w{proto_srv, proto_service_sig_chr, {0x00, 0x06, 0x0d, 0x10, 0x00}}; // good service signature request.
    // FakeWrite w{proto_srv, proto_service_sig_chr, {0x00, 0xf6, 0x0d, 0x10, 0x00}}; // bad service signature request, invalid Opcode
    //FakeWrite w{proto_srv, proto_service_sig_chr, {0x00, 0x01, 0x9c, 0xF1, 0x00}}; // bad characteristic request, invalid instance id

    // Good pair setup;
    //FakeWrite w{pairing_srv, pairing_srv_pair_setup_chr, {0x00, 0x02, 0xf3, 0x22, 0x00, 0x0b, 0x00, 0x01, 0x06, 0x00, 0x01, 0x00, 0x06, 0x01,  0x01, 0x09, 0x01, 0x01}};
    // Bad pair setup.
    // FakeWrite w{pairing_srv, pairing_srv_pair_setup_chr, {0x00, 0x02, 0xf3, 0x22, 0xff, 0x0b, 0x00, 0x01, 0x06, 0x00, 0x01, 0x00, 0x06, 0x01,  0x01, 0x09, 0x01, 0x01}}; // bad instance id.
    //FakeWrite w{pairing_srv, pairing_srv_pair_setup_chr, {0x00, 0x02, 0xf3, 0x22, 0x00, 0x0b, 0x00, 0x01, 0xf6, 0x00, 0x01, 0x00, 0x06, 0x01,  0x01, 0x09, 0x01, 0x01}};

    // Write to the lightbulb while not authenticated yet.
    //FakeWrite w{bulb_srv, bulb_srv_on_chr, {0x00, 0x02, 0xf3, 0x33, 0x00, 0x0b, 0x00, 0x01, 0xf6, 0x00, 0x01, 0x00, 0x06, 0x01,  0x01, 0x09, 0x01, 0x01}};
    //// Read the lightbulb while not authenticated.
    FakeWrite w{bulb_srv, bulb_srv_on_chr, {0x00, 0x03, 0xf3, 0x33, 0x00, 0x0b, 0x00, 0x01, 0xf6, 0x00, 0x01, 0x00, 0x06, 0x01,  0x01, 0x09, 0x01, 0x01}};

    const auto address = "00:00:00:00:00:00";
    on_local_char_write(c , address, w.service_uuid, w.char_uuid, w.payload);

    // Next, read the response.
    on_local_char_read(c , address, w.service_uuid, w.char_uuid);

    std::exit(0);
}


void writeSaltAndVerifier(const Bytes& salt, const Bytes& verifier) {
  HAPLogInfo(&logObject, "Writing salt and verifier to file");
  std::ofstream file("40.10", std::ios::binary);
  if (file.is_open()) {
      file.write(reinterpret_cast<const char*>(salt.data()), salt.size());
      file.write(reinterpret_cast<const char*>(verifier.data()), verifier.size());
      file.close();
  } else {
      HAPLogError(&logObject, "Unable to open file for writing");
  }
}

// This function is called when a read is done
// Use this to set the characteristic value if it is not set or to reject the read request
Bytes on_local_char_read(const OurBLEContainer* c, const char *address, const char *service_uuid,
                        const char *char_uuid) {

  CharacteristicId key = CharacteristicId::service_characteristic(service_uuid, char_uuid);
  std::string key_str = key;
  HAPLogError(&logObject, "Reading %s with %p", key_str.c_str(), c);

  const auto handle_it = c->characteristic_handles.find(key);
  HAPAssert(handle_it != c->characteristic_handles.end());

  const auto handle_id = handle_it->second;

  Bytes bytes;
  bytes.resize(kHAPPlatformBLEPeripheralManager_MaxAttributeBytes);
  size_t len = 0;

  HAPError err = c->delegate.handleReadRequest(
                      c->manager,
                      c->connection_handle,
                      handle_id,
                      bytes.data(),
                      kHAPPlatformBLEPeripheralManager_MaxAttributeBytes,
                      &len,
                      c->delegate.context);
  bytes.resize(len);
  HAPLogError(&logObject, "handleReadRequest returned %d, len is now: %zu", err, len);
  if (err != kHAPError_None ) {
    HAPAssert(err == kHAPError_InvalidState || err == kHAPError_OutOfResources);
    //return BLUEZ_ERROR_REJECTED;
    throw 1;
  }
  hexdump(bytes);
  return bytes;
}

// This function should be used to validate or reject a write request
bool on_local_char_write(const OurBLEContainer* c, const char *address, const char *service_uuid,
                          const char *char_uuid, Bytes byteArray) {
 // hexdump(byteArray);
  ///HAPLogError(&logObject, "write request characteristic <%s> with value <%s>", char_uuid, result->str);


  CharacteristicId key = CharacteristicId::service_characteristic(service_uuid, char_uuid);
  std::string key_str = key;
  HAPLogError(&logObject, "Writing to  %s with %p", key_str.c_str(), c);

  const auto handle_it = c->characteristic_handles.find(key);
  HAPAssert(handle_it != c->characteristic_handles.end());

  const auto handle_id = handle_it->second;

  uint8_t bytes[kHAPPlatformBLEPeripheralManager_MaxAttributeBytes] = { 0 };
  size_t len = byteArray.size();
  // Copy from the gbyte array into our buffer.
  memcpy(bytes, byteArray.data(), len);
  hexdump(byteArray );

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
      return false;
  }
  // Nothing further to do.

  return true;
}


extern "C" {
void HAPPlatformRandomNumberFill(void* bytes, size_t numBytes){
  std::uint8_t* dest = reinterpret_cast<std::uint8_t*>(bytes);
  //random_bytes
  for (std::size_t i = 0; i < numBytes; i++){
    dest[i] = random_bytes.front();
    random_bytes.pop_front();
  }
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

  std::cout << "create" << std::endl;

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
  HAPLogInfo(&logObject, "l: %d ", __LINE__);


  //c->service();
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
  OurBLEContainer* c = blePeripheralManager->container;

  const char* recent_service = c->recent_service.str;

  std::string behaviour = to_string(properties);
  HAPLogInfo(&logObject, "add characteristic, const bytes: %lu  behaviour: %s", constNumBytes, behaviour.c_str());
  hexdump(type->bytes, 16);


  RawUUID b = RawUUID::fromBytes(type->bytes);
  c->recent_characteristic = b;
//  guint permissions = makePermission(properties);
 // int res = binc_application_add_characteristic(c->app, recent_service,
  //                                        b.str, permissions);
int res = 0;
  HAPAssert(res == 0);
  CharacteristicId key;
  key.service = c->recent_service;
  key.characteristic = b;
  if (constNumBytes != 0) {
    HAPLogError(&logObject, "Have const data that needs handling.");
    hexdump(constBytes, constNumBytes);
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
  //guint permissions = makePermissionDescr(properties);

  CharacteristicId char_key;
  char_key.service = c->recent_service;
  char_key.characteristic = c->recent_characteristic;
  DescriptorId key = DescriptorId::characteristic_descriptor(char_key, b.str);

  int res = 0;
  HAPAssert(res == 0);

  if (constNumBytes != 0) {
    HAPLogInfo(&logObject, "Setting const data for descriptor: %s", std::string(b).c_str());
    hexdump(constBytes, constNumBytes);
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

    c->registered_application = true;
  }

  // Lets also start a background thread to push the event loop service onto the HAP service loop.
  if (!c->started_main_loop) {

    int r = HAPPlatformRunLoopScheduleCallback(run_main_loop, &c, sizeof(void*));
    HAPAssert(r == kHAPError_None);
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

  uint16_t COMPANY_IDENTIFIER_CODE =  0x004c;

  //HAPLogFault(&logObject, "pairable before %d", before);
}

void HAPPlatformBLEPeripheralManagerStopAdvertising(HAPPlatformBLEPeripheralManagerRef blePeripheralManager) {
  HAPPrecondition(blePeripheralManager);

  OurBLEContainer* c = blePeripheralManager->container;
  HAPLog(&logObject, __func__);

}

void HAPPlatformBLEPeripheralManagerCancelCentralConnection(
        HAPPlatformBLEPeripheralManagerRef blePeripheralManager,
        HAPPlatformBLEPeripheralManagerConnectionHandle connectionHandle HAP_UNUSED) {
  HAPPrecondition(blePeripheralManager);
  HAPLog(&logObject, __func__);

  // Request a disconnect.
  OurBLEContainer* c = blePeripheralManager->container;
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


} // extern C
