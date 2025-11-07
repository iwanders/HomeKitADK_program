

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
#include "HAPPlatformLinuxShared.h"


static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "BLEPeripheralManager" };



struct ReplayController {


};

static ReplayController control;

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
    GByteArray *cudArray = g_byte_array_sized_new(constNumBytes);
    g_byte_array_append(cudArray, reinterpret_cast<const unsigned char*>(constBytes), constNumBytes);
 
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

    c->registered_application = true;
  }

    /*
const char *on_local_char_write(const Application *application, const char *address, const char *service_uuid,
                          const char *char_uuid, GByteArray *byteArray) {
  */

  // Lets also start a background thread to push the event loop service onto the HAP service loop.
  if (!c->started_main_loop) {

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
  HAPPrecondition(c->default_adapter);
  HAPPrecondition(c->advertisement);
  HAPLog(&logObject, __func__);


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
