# homekit adk build

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ../ && make && ../provision.sh --ip --category 8  --setup-code 111-22-333
cmake -DCMAKE_BUILD_TYPE=Debug ../ && make && ./main
```


Assert on line 518 of HAPOpenSSL.c.

https://github.com/openssl/openssl/issues/20084
