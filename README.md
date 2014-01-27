pktutil
=======

Build
-----

```shell
git clone http://github.com/colemickens/pcapfe
cd pcapfe
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

