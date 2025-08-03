#!/bin/bash -xe

# This is hacked up from HomeKitADK/Tools/provision_raspi.sh

# This default assumes we're in a build directory inside the repo.
ADK_ROOT="${HOMEKIT_ADK_ROOT:-../HomeKitADK}"
sdkDomainsFile="${ADK_ROOT}/PAL/Raspi/HAPPlatformKeyValueStore+SDKDomains.h"

keyValueStore=".HomeKitStore"

if [[ $# -le 3 ]]; then
    echo "Pass more arguments, like so:" >&2
    echo "../provision.sh --ip --category 8  --setup-code 111-22-333" >&2
    exit 2
fi

accessorySetupGenerator=./setup_generator

flags=$*

# shellcheck disable=SC2086
accessorySetup=$("${accessorySetupGenerator}" ${flags})
# shellcheck disable=SC2206
accessorySetup=(${accessorySetup})

accessorySetupVersion="${accessorySetup[0]}"
if [ "${accessorySetupVersion}" != "1" ]; then
    fail "Incompatible with Accessory Setup Generator."
fi

setupCode="${accessorySetup[1]}"
srpSalt="${accessorySetup[2]}"
srpVerifier="${accessorySetup[3]}"
setupID="${accessorySetup[4]}"
setupPayload="${accessorySetup[5]}"

echo ${setupPayload}

################################################################################
# Provision accessory setup information.
################################################################################
provisioningDomainID="$(grep ${HOMEKIT_ADK_ROOT} "#define kSDKKeyValueStoreDomain_Provisioning " "${sdkDomainsFile}")"
[[ "${provisioningDomainID}" =~ "(HAPPlatformKeyValueStoreDomain) "0x([0-9]+) ]]
provisioningDomain="${BASH_REMATCH[1]}"

setupInfoKeyID="$(grep "#define kSDKKeyValueStoreKey_Provisioning_SetupInfo " "${sdkDomainsFile}")"
[[ "${setupInfoKeyID}" =~ "(HAPPlatformKeyValueStoreKey) "0x([0-9]+) ]]
setupInfoKey="${BASH_REMATCH[1]}"

setupIDKeyID="$(grep "#define kSDKKeyValueStoreKey_Provisioning_SetupID " "${sdkDomainsFile}")"
[[ "${setupIDKeyID}" =~ "(HAPPlatformKeyValueStoreKey) "0x([0-9]+) ]]
setupIDKey="${BASH_REMATCH[1]}"

setupCodeKeyID="$(grep "#define kSDKKeyValueStoreKey_Provisioning_SetupCode " "${sdkDomainsFile}")"
[[ "${setupCodeKeyID}" =~ "(HAPPlatformKeyValueStoreKey) "0x([0-9]+) ]]
setupCodeKey="${BASH_REMATCH[1]}"

mfiTokenUUIDKeyID="$(grep "#define kSDKKeyValueStoreKey_Provisioning_MFiTokenUUID " "${sdkDomainsFile}")"
[[ "${mfiTokenUUIDKeyID}" =~ "(HAPPlatformKeyValueStoreKey) "0x([0-9]+) ]]
mfiTokenUUIDKey="${BASH_REMATCH[1]}"

mfiTokenKeyID="$(grep "#define kSDKKeyValueStoreKey_Provisioning_MFiToken " "${sdkDomainsFile}")"
[[ "${mfiTokenKeyID}" =~ "(HAPPlatformKeyValueStoreKey) "0x([0-9]+) ]]
mfiTokenKey="${BASH_REMATCH[1]}"

setupInfoFile="${keyValueStore}/${provisioningDomain}.${setupInfoKey}"
setupIDFile="${keyValueStore}/${provisioningDomain}.${setupIDKey}"
setupCodeFile="${keyValueStore}/${provisioningDomain}.${setupCodeKey}"
mfiTokenUUIDFile="${keyValueStore}/${provisioningDomain}.${mfiTokenUUIDKey}"
mfiTokenFile="${keyValueStore}/${provisioningDomain}.${mfiTokenKey}"

command=""

#command="${command}"'rm -rf '"${setupInfoFile}"' '"${setupIDFile}"' '"${setupCodeFile}"' && '
if (( ! preserveMFiToken )); then
#    command="${command}"'rm -rf '"${mfiTokenUUIDFile}"' '"${mfiTokenFile}"' && '
  command="${command} "
fi
command="${command}"'mkdir -p '"${keyValueStore}"' && '
if (( ! supportsDisplay )); then
    command="${command}"'echo -n "'"${srpSalt}${srpVerifier}"'" | '
    # shellcheck disable=SC2016
    command="${command}"'perl -ne '"'"'s/([0-9a-f]{2})/print chr hex $1/gie'"'"' > '"${setupInfoFile}"' && '
    if (( supportsProgrammableNFC )); then
        command="${command}"'echo -en "'"${setupCode}"'\0" > '"${setupCodeFile}"' && '
    fi
fi
command="${command}"'echo -en "'"${setupID}"'\0" > '"${setupIDFile}"' && '
if [ "${mfiTokenUUID}" != "" ] && [ "${mfiToken}" != "" ]; then
    command="${command}"'echo -n "'"${mfiTokenUUID}"'" | '
    # shellcheck disable=SC2016
    command="${command}"'perl -ne '"'"'s/([0-9a-f]{2})/print chr hex $1/gie'"'"' > '"${mfiTokenUUIDFile}"' && '
    command="${command}"'echo -n "'"${mfiToken}"'" | '
    # shellcheck disable=SC2016
    command="${command}"'perl -ne '"'"'s/([0-9a-f]{2})/print chr hex $1/gie'"'"' > '"${mfiTokenFile}"' && '
fi
command="${command}"'true'

echo "cmd: ${command}"
if ! eval "${command}"; then
    fail "Failed to provision ${destination}."
fi

