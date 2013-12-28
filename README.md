pcapfe
======

libpcap bindings for Rust. This probably only works under Linux under a recent kernel.

This was inspired by d3cap, but shares no code with it other than the libpcap function defintions.

thanks: aatch, chrismorgan, other #rust ppl at large

```rust
git clone http://github.com/colemickens/pcapfe
cd pcapfe
rustpkg build
rustpkg test
`