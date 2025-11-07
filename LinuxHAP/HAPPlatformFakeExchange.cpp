

#include <map>
#include <unistd.h>
#include <vector>
#include <string>
#include <memory>
#include <thread>
#include <sstream>
#include <iostream>
#include <iomanip>

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


void  run_main_loop(void* _Nullable context, size_t contextSize) {
  usleep(1000000);
  // THis is a pointer to a pointer.
  OurBLEContainer* c = *reinterpret_cast<OurBLEContainer**>(context);
  std::cout << "Doing c->delegate.handleConnectedCentral " << c->delegate.handleConnectedCentral << std::endl;
  std::cout << "Doing c->manager " << c->manager << std::endl;

  if (c->delegate.handleConnectedCentral && c->manager) {
    std::cout << "cc things" << std::endl;

    c->connection_handle++;
    (*(c->delegate.handleConnectedCentral))(c->manager, c->connection_handle, c->delegate.context);




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

  }


  int r = HAPPlatformRunLoopScheduleCallback(run_main_loop, &c,sizeof(void*));
  HAPAssert(r == kHAPError_None);
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
