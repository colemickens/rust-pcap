#[feature(globs)];

#[link(name="pcapfe", vers="0.0.1")];

extern mod std;

use std::libc::{c_char,c_int,c_ulonglong};
use std::{ptr,vec};

use pcap::*;
mod pcap;

pub enum PcapNextExError {
    BadState,
    ReadError,
    Timeout,
    EndOfCaptureFile,
    Unknown
}

pub enum PcapFilterError {
    DeviceClosed, // this is a dup of the above?
    CompileError,
    SetError
}

pub struct PcapDevice {
    pcap_dev: *pcap_t,
    closed: bool
}

pub struct PcapPacket {
    timestamp: Struct_timeval,
    len: uint,
    payload: ~[u8]
}

impl PcapPacket {
    pub fn get_source_mac() -> ~[u8] {
        // figure out the offset
        // wowsers I've got a headache, do this later
        // TODO: finish tomorrow 
        ~[01u8, 01u8, 01u8, 01u8, 01u8, 01u8]
    }

    pub fn get_destination_mac() -> ~[u8] {
        ~[01u8, 01u8, 01u8, 01u8, 01u8, 01u8]
    }
}

// expand this to take more of the args for open_live?
pub fn PcapOpenDevice(dev: &str) -> Option<PcapDevice> {
    let errbuf = vec::with_capacity(256);
    let eb = vec::raw::to_ptr(errbuf);
    let c_dev = unsafe { dev.to_c_str().unwrap() };
    let handle = unsafe { pcap_open_live(c_dev, 65536, 0, 1000, eb) };
    // should probably do something with error buffer?
    if handle == ptr::null() {
        None
    } else {
        let pd: PcapDevice = PcapDevice { pcap_dev: handle, closed: false };
        Some(pd)
    }
}

impl PcapDevice {
    pub fn SetFilter(&self, dev: &str, filter_str: &str) -> Result<(), PcapFilterError> {
        unsafe {
            if self.closed {
                return Err(DeviceClosed)
            }
            let errbuf = vec::with_capacity(256);
            let eb = vec::raw::to_ptr(errbuf);
            let netp: c_int = 0;
            let maskp: c_int = 0;
            //let filter_program: Struct_bpf_program = std::unstable::intrinsics::uninit(); //wut why not *Struct_bpf_program
            let filter_program: Struct_bpf_program = std::unstable::intrinsics::uninit();
            let c_dev = dev.to_c_str().unwrap();
            let c_filter_str = filter_str.to_c_str().unwrap();
            
            pcap_lookupnet(c_dev, &netp, &maskp, eb);
            let res = pcap_compile(self.pcap_dev, &filter_program, c_filter_str, 0, &netp);
            if res != 0 {
                Err(CompileError)
            } else {
                let res = pcap_setfilter(self.pcap_dev, &filter_program);
                if res != 0 {
                    Err(SetError) // how to set the errorbuf msg in the SetError somehow?
                } else {
                    Ok(())
                }
            }
        }
    }

    pub fn NextPacketEx(&self) -> Result<PcapPacket, PcapNextExError> {
        if self.closed {
            Err(BadState) // will this fail too?
        } else {
            unsafe {
                let pkthdr_ptr: Struct_pcap_pkthdr = std::unstable::intrinsics::uninit();
                let pkt_data_ptr: *u8 = std::unstable::intrinsics::uninit();

                let result = pcap_next_ex(self.pcap_dev, &pkthdr_ptr, &pkt_data_ptr);
                let pkt_len: uint = (*pkthdr_ptr).len as uint;
                match result {
                    -2 => { Err(EndOfCaptureFile) }
                    -1 => { Err(ReadError) } // call pcap_geterr() or pcap_perror()
                    0 => { Err(Timeout) }
                    1 => {
                        let payload = std::vec::from_buf(pkt_data_ptr, pkt_len); // this probably doesn't copy as I need
                        let pkt = PcapPacket{
                            timestamp: (*pkthdr_ptr).ts,
                            len: pkt_len,
                            payload: payload
                        };
                        Ok(pkt)
                    }
                    _ => { Err(Unknown) }
                }
            }
        }
    }

    // Should this be impl Drop for PcapDevice?
    pub fn Close(&mut self) {
        unsafe {
            self.closed = true;
            pcap_close(self.pcap_dev);
        }
    }
}