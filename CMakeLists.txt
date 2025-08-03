PROJECT("homekit_adk_linux_test")

add_library(homekit_linux STATIC
  ./HomeKitADK/PAL/Linux/HAPPlatform.c
  ./HomeKitADK/PAL/Linux/HAPPlatformAbort.c
  ./HomeKitADK/PAL/Linux/HAPPlatformAccessorySetup.c
  ./HomeKitADK/PAL/Linux/HAPPlatformAccessorySetupDisplay.c
  ./HomeKitADK/PAL/Linux/HAPPlatformAccessorySetupNFC.c
  ./HomeKitADK/PAL/Linux/HAPPlatformBLEPeripheralManager.c
  ./HomeKitADK/PAL/Linux/HAPPlatformClock.c
  ./HomeKitADK/PAL/Linux/HAPPlatformFileManager.c
  ./HomeKitADK/PAL/Linux/HAPPlatformKeyValueStore.c
  ./HomeKitADK/PAL/Linux/HAPPlatformLog.c
  ./HomeKitADK/PAL/Linux/HAPPlatformMFiHWAuth.c
  ./HomeKitADK/PAL/Linux/HAPPlatformMFiTokenAuth.c
  ./HomeKitADK/PAL/Linux/HAPPlatformRandomNumber.c
  ./HomeKitADK/PAL/Linux/HAPPlatformRunLoop.c
  ./HomeKitADK/PAL/Linux/HAPPlatformServiceDiscovery.c
  ./HomeKitADK/PAL/Linux/HAPPlatformSystemCommand.c
  ./HomeKitADK/PAL/Linux/HAPPlatformTCPStreamManager.c
)
target_include_directories(homekit_linux PUBLIC
  ./HomeKitADK/PAL/Linux/
  ./HomeKitADK/PAL/
  ./HomeKitADK/HAP/
)

add_library(homekit_util STATIC
  ./HomeKitADK/External/Base64/util_base64.c
  ./HomeKitADK/External/HTTP/util_http_reader.c
  ./HomeKitADK/External/JSON/util_json_reader.c
)
target_include_directories(homekit_util PUBLIC
  ./HomeKitADK/External/Base64/
  ./HomeKitADK/External/HTTP
  ./HomeKitADK/External/JSON/
  ./HomeKitADK/PAL/
  ./HomeKitADK/HAP/
)

add_library(homekit_adk STATIC
./HomeKitADK/HAP/HAPAccessory+Info.c
./HomeKitADK/HAP/HAPAccessoryServer.c
./HomeKitADK/HAP/HAPAccessoryServer+Reset.c
./HomeKitADK/HAP/HAPAccessorySetup.c
./HomeKitADK/HAP/HAPAccessorySetupInfo.c
./HomeKitADK/HAP/HAPAccessoryValidation.c
./HomeKitADK/HAP/HAPBitSet.c
./HomeKitADK/HAP/HAPBLEAccessoryServer.c
./HomeKitADK/HAP/HAPBLEAccessoryServer+Advertising.c
./HomeKitADK/HAP/HAPBLEAccessoryServer+Broadcast.c
./HomeKitADK/HAP/HAPBLECharacteristic.c
./HomeKitADK/HAP/HAPBLECharacteristic+Broadcast.c
./HomeKitADK/HAP/HAPBLECharacteristic+Configuration.c
./HomeKitADK/HAP/HAPBLECharacteristicParseAndWriteValue.c
./HomeKitADK/HAP/HAPBLECharacteristicReadAndSerializeValue.c
./HomeKitADK/HAP/HAPBLECharacteristic+Signature.c
./HomeKitADK/HAP/HAPBLEPDU.c
./HomeKitADK/HAP/HAPBLEPDU+TLV.c
./HomeKitADK/HAP/HAPBLEPeripheralManager.c
./HomeKitADK/HAP/HAPBLEProcedure.c
./HomeKitADK/HAP/HAPBLEProtocol+Configuration.c
./HomeKitADK/HAP/HAPBLEService+Signature.c
./HomeKitADK/HAP/HAPBLESession.c
./HomeKitADK/HAP/HAPBLETransaction.c
./HomeKitADK/HAP/HAPCharacteristic.c
./HomeKitADK/HAP/HAPCharacteristicTypes.c
./HomeKitADK/HAP/HAPDeviceID.c
./HomeKitADK/HAP/HAPIPAccessory.c
./HomeKitADK/HAP/HAPIPAccessoryProtocol.c
./HomeKitADK/HAP/HAPIPAccessoryServer.c
./HomeKitADK/HAP/HAPIP+ByteBuffer.c
./HomeKitADK/HAP/HAPIPCharacteristic.c
./HomeKitADK/HAP/HAPIPSecurityProtocol.c
./HomeKitADK/HAP/HAPIPServiceDiscovery.c
./HomeKitADK/HAP/HAPJSONUtils.c
./HomeKitADK/HAP/HAPLegacyImport.c
./HomeKitADK/HAP/HAPMACAddress.c
./HomeKitADK/HAP/HAPMFiHWAuth.c
./HomeKitADK/HAP/HAPMFiTokenAuth.c
./HomeKitADK/HAP/HAPPairing.c
./HomeKitADK/HAP/HAPPairingBLESessionCache.c
./HomeKitADK/HAP/HAPPairingPairings.c
./HomeKitADK/HAP/HAPPairingPairSetup.c
./HomeKitADK/HAP/HAPPairingPairVerify.c
./HomeKitADK/HAP/HAPPDU.c
./HomeKitADK/HAP/HAPRequestHandlers.c
./HomeKitADK/HAP/HAPRequestHandlers+AccessoryInformation.c
./HomeKitADK/HAP/HAPRequestHandlers+HAPProtocolInformation.c
./HomeKitADK/HAP/HAPRequestHandlers+Pairing.c
./HomeKitADK/HAP/HAPServiceTypes.c
./HomeKitADK/HAP/HAPSession.c
./HomeKitADK/HAP/HAPStringBuilder.c
./HomeKitADK/HAP/HAPTLV.c
./HomeKitADK/HAP/HAPTLVMemory.c
./HomeKitADK/HAP/HAPTLVReader.c
./HomeKitADK/HAP/HAPTLVWriter.c
./HomeKitADK/HAP/HAPUUID.c
./HomeKitADK/HAP/HAPVersion.c
)
target_link_libraries(homekit_adk PUBLIC homekit_util)

target_include_directories(homekit_adk PUBLIC
  ./HomeKitADK/PAL/Linux/
  ./HomeKitADK/PAL/
  ./HomeKitADK/HAP/
)
