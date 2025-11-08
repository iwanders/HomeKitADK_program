# HomeKitADK Program

This repo is a _very hacky_ repo to run the examples from the `HomeKitADK`. Goal is to get a capture of packets of the
reference implementation, nothing more.

It now also contains an example that allows playing messages against the reference implementation. See the `replay` section
at the bottom of this page.

## Wifi

This is mostly just works because the Linux PAL from upstream handles network.

Upstream [apple/HomeKitADK](https://github.com/apple/HomeKitADK) needs some patches to run these days.

1. Clone this repository recursively.
2. Install Prerequisites, `libbluetooth-dev libavahi-compat-libdnssd-dev libssl-dev`.
3. Run `./apply_patch.sh`, this prevents the assert on line 518 of `HAPOpenSSL.c`, openssl no longer support a non standard nonce. [ticket](https://github.com/openssl/openssl/issues/20084).
4. Provision and build with:

```
mkdir build
cd build
rm -f .HomeKitStore/* && ../provision.sh --ip --category 2  --setup-code 111-22-333
cmake -DCMAKE_BUILD_TYPE=Debug ../ && make && ./main
```

Next, the device should show up for pairing in the Home app on an iOS device.

## Bluetooth

~Okay, this is a bit of a stretch and not working yet.~ This is working-ish, it's very flaky (comission flaky, not code-flaky). But good enough to capture the packet contents of a comissioning procedure. Maybe it's flaky because we can't set the device address at
the moment?

This requires some further changes, the upstream PAL does not support bluetooth. So to achieve this we need to add bluetooth
handling. We use [bluez_inc](https://github.com/weliem/bluez_inc) to get a nice C api to create our bluetooth peripheral over
dbus.

Apply patches with the shell script, and build with the BLE option in the cmakelists.
```
./apply_patch_ble.sh
reset; cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_BLE=YES ../ && VERBOSE=1 make && ./main_ble
```

Initially I always got a pairing procedure while connecting in the nRF Connect app, but a bluetooth example from
[this repo](https://github.com/spacecheese/bluez_peripheral/pull/43) can be connected to without pairing, so we need
to toggle that attribute on the adapter as homekit peripherals don't pair.


I also toggled [ReverseServiceDiscovery](https://github.com/bluez/bluez/issues/851) to false, but I'm not sure if that's
better or worse.


Originally, I tried disabling pairable with
```
busctl set-property org.bluez /org/bluez/hci0 org.bluez.Adapter1 Pairable 'b' 0
```
Added a method to bluez_inc for this now.


## How to
Okay, so this is all super flaky, the Home app has a tendency to disconnect from the peripheral, I'm not sure why.
Best steps seem to be:
1. ~Restart the bluetooth service on PC~ Doesn't seem to matter much.
2. Clear `.HomeKitStore` and reprovision, this ensures the iPhone doesn't consider it an 'already forgotten' device.
3. Open homekit to 'see' the device, try to pair.
4. Swap to the NRF connect application to connect to the device.
5. Perform the pairing in homekit, if this fails, go back to 4.

## Mock request
Very sketchy fake request insertion using the hardcoded request from `perform_fake_request` and run with:
```
cmake -DCMAKE_BUILD_TYPE=Debug ../ && make && DO_FAKE_REQUEST=1 ./main_ble
```

## Replay
This just replaces the hap platform peripheral manager.
```
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_REPLAY=ON ../ && make && ENABLE_REPLAY=1 ./main_ble
```
This replays an entire pairing procedure including lightbulb toggles. This was mostly built to figure out the
