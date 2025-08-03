# homekit adk build

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ../ && make && rm -f .HomeKitStore/* && ../provision.sh --ip --category 2  --setup-code 111-22-333
cmake -DCMAKE_BUILD_TYPE=Debug ../ && make && ./main
```


Assert on line 518 of HAPOpenSSL.c.

https://github.com/openssl/openssl/issues/20084

To fix that:

```
./apply_patches.sh
```
