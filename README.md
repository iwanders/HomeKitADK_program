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

### Building BLuez
The `shared/gatt-db.h` headers are considered internal and not available by just using the `-dev` package.

Get the source code from https://github.com/bluez/bluez checkout a version close to the one you are running, `5.66`.

```
apt install autotools-dev automake libtool libjson-c-dev libical-dev libreadline-dev python3-docutils libsbc-dev libspeexdsp-dev libell-dev
```

```
./bootstrap-configure --enable-external-ell --enable-static  --enable-library  --disable-asan --disable-lsan --disable-ubsan
make -j30
# Move relevant stuff
make install DESTDIR=$PWD/x
# Copy static libraries to destination.
cp ./lib/.libs/* ./x/usr/lib/
cp ./src/.libs/* ./x/usr/lib/
# Clean up intermediate build artifacts
make clean
```
### Compiling
```
./apply_patch_ble.sh
reset; cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_BLE=YES ../ && VERBOSE=1 make && ./main_ble
```
