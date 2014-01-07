pcapfe
======

libpcap bindings for Rust. This probably only works under Linux under a recent kernel.

Thanks to all in #rust.

```shell
git clone http://github.com/colemickens/pcapfe
cd pcapfe
make # RIP rustpkg
```

pcap.rs - generated
pcapfe.rs - my wrapper for pcap

pktutil.rs - decode
pktutil_test.rs - a few tests for my decode/encode