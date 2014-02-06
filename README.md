rust-pcap
=========

[![Build Status](https://secure.travis-ci.org/colemickens/rust-pcap.png)](http://travis-ci.org/colemickens/rust-pcap)

Build
-----

```shell
git clone http://github.com/colemickens/rust-pcap
cd rust-pcap
rustpkg build
```

Bindgen
-------

Generating the c-bindings via rust-bindgen:

```shell
../../../crabtw/src/rust-bindgen/bindgen \
  -builtins \
  -l pcap \
  -o pcap.rs \
  /usr/include/pcap/pcap.h \
  -I/usr/lib/clang/3.4/include/
```
