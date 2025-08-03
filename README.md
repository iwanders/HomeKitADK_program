# homekit adk build

Prerequisites, `libbluetooth-dev libavahi-compat-libdnssd-dev libssl-dev`.

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ../ && make && rm -f .HomeKitStore/* && ../provision.sh --ip --category 2  --setup-code 111-22-333
cmake -DCMAKE_BUILD_TYPE=Debug ../ && make && ./main
```


Assert on line 518 of HAPOpenSSL.c.

https://github.com/openssl/openssl/issues/20084

To fix that, we apply a patch to fix that initialisation vectors, see `HAPOpenSSL.patch`.s


We also swap some files from the Linux HAP with

```
./apply_patches.sh
```


# Building BLuez
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
