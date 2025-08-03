PROJECT("homekit_adk_linux_test")

# Set global log level to 3.
add_compile_definitions(HAP_LOG_LEVEL=3)

# HAP OpenSSL needs this. (libssl-dev)
find_package(OpenSSL REQUIRED)

# avahi libavahi-compat-libdnssd-dev


find_package(PkgConfig REQUIRED)
pkg_check_modules(DSNSD REQUIRED avahi-compat-libdns_sd)

message(WARN "flskjglsdf ${DSNSD_Libs}")

#get_cmake_property(_variableNames VARIABLES)
#list (SORT _variableNames)
#foreach (_variableName ${_variableNames})
#    message(STATUS "${_variableName}=${${_variableName}}")
#endforeach()

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


add_library(homekit_pal STATIC
  ./HomeKitADK/PAL/HAPAssert.c
  ./HomeKitADK/PAL/HAPBase+Crypto.c
  ./HomeKitADK/PAL/HAPBase+Double.c
  ./HomeKitADK/PAL/HAPBase+Float.c
  ./HomeKitADK/PAL/HAPBase+Int.c
  ./HomeKitADK/PAL/HAPBase+MACAddress.c
  ./HomeKitADK/PAL/HAPBase+RawBuffer.c
  ./HomeKitADK/PAL/HAPBase+Sha1Checksum.c
  ./HomeKitADK/PAL/HAPBase+String.c
  ./HomeKitADK/PAL/HAPBase+UTF8.c
  ./HomeKitADK/PAL/HAPLog.c
  ./HomeKitADK/PAL/HAPPlatformSystemInit.c
)

target_link_libraries(homekit_pal PUBLIC homekit_linux )


add_library(homekit_crypto STATIC
  ./HomeKitADK/PAL/Crypto/OpenSSL/HAPOpenSSL.c
  # Lets see if we can stick to open openssl.
  #./HomeKitADK/PAL/Crypto/MbedTLS/HAPMbedTLS.c
  #./HomeKitADK/PAL/Crypto/MbedTLS/Ed25519/curve25519_mehdi.c
  #./HomeKitADK/PAL/Crypto/MbedTLS/Ed25519/curve25519_order.c
  #./HomeKitADK/PAL/Crypto/MbedTLS/Ed25519/curve25519_utils.c
  #./HomeKitADK/PAL/Crypto/MbedTLS/Ed25519/ed25519_sign.c
  #./HomeKitADK/PAL/Crypto/MbedTLS/Ed25519/ed25519_verify.c
)
target_include_directories(homekit_crypto PUBLIC
  ./HomeKitADK/PAL/Crypto/MbedTLS/Ed25519/
  ./HomeKitADK/PAL/Crypto/MbedTLS/
)
target_include_directories(homekit_crypto PUBLIC
  ./HomeKitADK/PAL/
  ./HomeKitADK/HAP/
)
target_link_libraries(homekit_crypto PUBLIC homekit_util OpenSSL::SSL)




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
target_link_libraries(homekit_linux PUBLIC  ${DSNSD_LIBRARIES})

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
target_link_libraries(homekit_adk PUBLIC homekit_util  homekit_crypto homekit_pal)

target_include_directories(homekit_adk PUBLIC
  ./HomeKitADK/PAL/Linux/
  ./HomeKitADK/PAL/
  ./HomeKitADK/HAP/
)

add_executable(main
  ./HomeKitADK/Applications/Lightbulb/Main.c
  ./HomeKitADK/Applications/Lightbulb/App.c
  ./HomeKitADK/Applications/Lightbulb/DB.c
)
target_link_libraries(main PRIVATE homekit_adk homekit_linux homekit_pal)
target_compile_definitions(main PUBLIC IP )

add_executable(setup_generator
  ./HomeKitADK/Tools/AccessorySetupGenerator/Main.c
)
target_link_libraries(setup_generator PRIVATE homekit_adk homekit_linux homekit_pal)
#/setup_generator  --ip --category 8  --setup-code 111-22-333
# --category 5 .HomeKitStore