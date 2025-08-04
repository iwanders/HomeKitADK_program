# HomeKitADK Program

This repo is a _very hacky_ repo to run the examples from the `HomeKitADK`.

Upstream [apple/HomeKitADK](https://github.com/apple/HomeKitADK) needs some patches to run these days.

1. Clone this repository recursively.
2. Install Prerequisites, `libbluetooth-dev libavahi-compat-libdnssd-dev libssl-dev`.
3. Run `./apply_patch.sh`, this prevents the assert on line 518 of `HAPOpenSSL.c`, openssl no longer support a non standard nonce. [ticket](https://github.com/openssl/openssl/issues/20084).
4. Provision and build with:

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ../ && make && rm -f .HomeKitStore/* && ../provision.sh --ip --category 2  --setup-code 111-22-333
cmake -DCMAKE_BUILD_TYPE=Debug ../ && make && ./main
```

Next, the device should show up for pairing in the Home app on an iOS device.

## Bluetooth

Okay, this is a bit of a stretch and not working yet.

We always get pairing... https://github.com/spacecheese/bluez_peripheral/pull/43/files allows for connecting without pairing.


https://github.com/bluez/bluez/issues/851

Disable pairable with
```
busctl set-property org.bluez /org/bluez/hci0 org.bluez.Adapter1 Pairable 'b' 0
```
Added a method to bluez_inc for this now.

Switched to https://github.com/weliem/bluez_inc for the bluetooth handling.

### Compiling
```
./apply_patch_ble.sh
reset; cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_BLE=YES ../ && VERBOSE=1 make && ./main_ble
```
