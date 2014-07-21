#![allow(non_camel_case_types)]
#![allow(dead_code)]

#[cfg(windows)]
#[link(name = "wpcap")]
extern "C" {}

#[cfg(not(windows))]
#[link(name = "pcap")]
extern "C" {}
