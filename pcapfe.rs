#[crate_id="pcapfe"];
#[crate_type="lib"];
#[desc = "A Rust package wrapping libpcap"];
#[license = "MIT"];

#[feature(globs)];

extern mod std;

use std::io::net::ip;
use std::io::net::ip::Ipv4Addr;
use std::libc::{c_uint,c_char,c_schar,c_void };
use std::ptr;
use std::str;
use std::vec;

use pcap::*;
mod pcap;

pub enum PcapError {
    NextEx_BadState,
    NextEx_ReadError,
    NextEx_Timeout,
    NextEx_EndOfCaptureFile,
    Filter_DeviceClosed,
    Filter_CompileError,
    Filter_SetError,
    Unknown
}

//
// HELP: Should I split the above (packet decoding) into a separate lib? from the pcap binding wrapper?
//

pub struct PcapDevice {
    pcap_dev: *mut pcap_t,
    closed: bool
}

pub struct PcapPacket {
    timestamp: Struct_timeval,
    len: uint,
    payload: ~[u8]
}

pub fn pcap_open_dev(dev: &str) -> Result<PcapDevice, ~str> {
    pcap_open_dev_adv(dev, 65536, 0, 1000)
}

pub fn pcap_open_dev_adv(dev: &str, size: int, flag: int, mtu: int) -> Result<PcapDevice, ~str> {
    unsafe {
        let mut errbuf: ~[c_char] = vec::with_capacity(256);
        let c_dev = dev.to_c_str().unwrap();
        let handle = pcap_open_live(c_dev, size as i32, flag as i32, mtu as i32, errbuf.as_mut_ptr());
        
        let errbuf_f: ~[u8] = std::cast::transmute(errbuf);
        if handle == ptr::mut_null() {
            Err(prettystr(errbuf_f)) // TODO: fix [this is always empty]
        } else {
            let pd: PcapDevice = PcapDevice { pcap_dev: handle, closed: false };
            Ok(pd)
        }
    }
}

impl PcapDevice {
    pub fn set_filter(&self, dev: &str, filter_str: &str) -> Result<(), PcapError> {
        unsafe {
            if self.closed {
                return Err(Filter_DeviceClosed)
            }
            let mut errbuf: ~[c_char] = vec::with_capacity(256);
            let mut netp: c_uint = 0;
            let mut maskp: c_uint = 0;
            let mut filter_program: Struct_bpf_program = std::unstable::intrinsics::uninit();

            let c_dev = dev.to_c_str().unwrap();
            let c_filter_str = filter_str.to_c_str().unwrap();
            
            pcap_lookupnet(c_dev, &mut netp, &mut maskp, errbuf.as_mut_ptr());
            let res = pcap_compile(self.pcap_dev, &mut filter_program, c_filter_str, 0, netp);
            if res != 0 {
                Err(Filter_CompileError)
            } else {
                let res = pcap_setfilter(self.pcap_dev, &mut filter_program);
                if res != 0 {
                    Err(Filter_SetError)
                } else {
                    Ok(())
                }
            }
        }
    }

    pub fn next_packet_ex(&self) -> Result<PcapPacket, PcapError> {
        if self.closed {
            Err(NextEx_BadState)
        } else {
            unsafe {
                let mut pkthdr_ptr: *mut Struct_pcap_pkthdr = std::unstable::intrinsics::uninit();
                let mut pkt_data_ptr: *u8 = std::unstable::intrinsics::uninit();

                let result = pcap_next_ex(self.pcap_dev, &mut pkthdr_ptr, &mut pkt_data_ptr);

                let pkt_len: uint = (*pkthdr_ptr).len as uint;
                match result {
                    -2 => { Err(NextEx_EndOfCaptureFile) }
                    -1 => { Err(NextEx_ReadError) } // call pcap_getErr(NextEx_) or pcap_perror() (ret Result instead)
                    0 => { Err(NextEx_Timeout) }
                    1 => {
                        if pkt_len == 0 {
                            println!("ignoring zero length packet"); 
                            Err(Unknown)
                        } else {
                            let payload = std::vec::from_buf(pkt_data_ptr, pkt_len);                            
                            let pkt = PcapPacket{
                                timestamp: (*pkthdr_ptr).ts,
                                len: pkt_len,
                                payload: payload
                            };
                            Ok(pkt)
                        }
                    }
                    _ => { Err(Unknown) }
                }
            }
        }
    }

    pub fn inject(&self, pkt: ~[u8]) -> Option<uint> {
        unsafe {
            let data1 = pkt.as_ptr() as *c_void;
            let size1 = pkt.len() as u64;
            let result = pcap_inject(self.pcap_dev, data1, size1);
            if result < 0 {
                None
            } else {
                Some(result as uint)
            }
        }
    }
}

impl Drop for PcapDevice {
    fn drop(&mut self) {
        unsafe {
            self.closed = true;
            pcap_close(self.pcap_dev);
        }
    }
}

// Doesn't belong:

pub fn prettystr(p: &[u8]) -> ~str {
    let p = p.map(|&e| if e > 31 && e < 127 { e } else { '.' as u8 });
    str::from_utf8_owned(p)
}