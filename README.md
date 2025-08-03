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
