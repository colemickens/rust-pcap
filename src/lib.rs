#![feature(globs)]

use std::libc::{c_uint,c_char,c_int};
use std::ptr;
use std::vec::Vec;

use pcap::*;
mod pcap;

#[allow(non_camel_case_types)]
pub enum PcapError {
    NextEx_BadState,
    NextEx_ReadError,
    NextEx_Timeout,
    NextEx_EndOfCaptureFile,
    Filter_DeviceClosed,
    Filter_CompileError,
    Filter_SetError,
    Datalink_SetError,
    Unknown
}

// turn this into an enum?
/*
pub enum DatalinkType {
    Datalink_Other,
    DatalinkType_Ethernet = 1,
    DatalinkType_IEEE802_11_RADIO = 127,
}
*/

pub type DatalinkType = u8;
pub static DLT_NULL: DatalinkType = 0;
pub static DLT_ETHERNET: DatalinkType = 1;
pub static DLT_IEEE802_11_RADIO: DatalinkType = 127;

pub struct PcapDevice {
    dev: *mut pcap_t,
    closed: bool
}

pub struct PcapPacket {
    timestamp: Struct_timeval,
    len: uint,
    payload: Vec<u8>
}

pub fn pcap_open_dev(dev: &str) -> Result<PcapDevice, ~str> {
    pcap_open_dev_adv(dev, 65536, 0, 1000)
}

pub fn pcap_open_dev_adv(dev: &str, size: int, flag: int, mtu: int) -> Result<PcapDevice, ~str> {
    unsafe {
        let mut errbuf: Vec<c_char> = Vec::with_capacity(256);
        let c_dev = dev.to_c_str().unwrap();
        let handle = pcap_open_live(c_dev, size as i32, flag as i32, mtu as i32, errbuf.as_mut_ptr());
        
        /*
        TODO:restore
        let _errbuf_f: ~[u8] = std::cast::transmute(errbuf);
        */
        if handle == ptr::mut_null() {
            //Err(prettystr(errbuf_f)) // TODO: fix [this is always empty]
            Err(~"err")
        } else {
            let pd: PcapDevice = PcapDevice { dev: handle, closed: false };
            Ok(pd)
        }
    }
}

impl PcapDevice {
    pub fn get_datalink(&self) -> Option<DatalinkType> {
        unsafe {
            match pcap_datalink(self.dev) {
                n if n < 0 => { None }
                m => { Some(m as u8) }
            }
        }
    }

    pub fn set_datalink(&self, dlt: DatalinkType) -> Result<(),PcapError> {
        unsafe {
            match pcap_set_datalink(self.dev, dlt as i32) {
                -1 => { Err(Datalink_SetError) }
                0 => { Ok(()) }
                _ => { Err(Unknown) }
            }
        }
    }

    pub fn list_datalinks(&self) -> ~[DatalinkType] {
        unsafe {
            let mut dlt_buf: *mut c_int = ptr::mut_null();
            let sz = pcap_list_datalinks(self.dev, &mut dlt_buf);
            // let out: ~[u8] = Vec::raw::from_buf_raw(dlt_buf as *u8, sz as uint);
            // TODO is this correct
            let out: Vec<u8> = Vec::from_raw_parts(sz as uint, sz as uint, dlt_buf as *mut u8);
            pcap_free_datalinks(dlt_buf);
            let mut out2: ~[DatalinkType] = ~[];
            for t in out.iter() {
                out2.push(*t as DatalinkType);
            }
            out2
        }
    }

    pub fn set_filter(&self, dev: &str, filter_str: &str) -> Result<(), PcapError> {
        unsafe {
            if self.closed {
                return Err(Filter_DeviceClosed)
            }
            let mut errbuf: Vec<c_char> = Vec::with_capacity(256);
            let mut netp: c_uint = 0;
            let mut maskp: c_uint = 0;
            let mut filter_program: Struct_bpf_program = std::intrinsics::uninit();

            let c_dev = dev.to_c_str().unwrap();
            let c_filter_str = filter_str.to_c_str().unwrap();
            
            pcap_lookupnet(c_dev, &mut netp, &mut maskp, errbuf.as_mut_ptr());
            let res = pcap_compile(self.dev, &mut filter_program, c_filter_str, 0, netp);
            if res != 0 {
                Err(Filter_CompileError)
            } else {
                let res = pcap_setfilter(self.dev, &mut filter_program);
                if res != 0 {
                    Err(Filter_SetError)
                } else {
                    Ok(())
                }
            }
        }
    }

    pub fn capture_loop<C>(&self, ctx: ~C, hndlr: pcap_handler) {
        // credit to huon (PST TIME #rust on mozilla.org)
        // [01:55:13] <huon> geomyidae: &*ctx as *C as *u8
        unsafe { pcap_loop(self.dev, -1, hndlr, &*ctx as *C as *mut u8); }
    }

    pub fn next_packet_ex(&self) -> Result<PcapPacket, PcapError> {
        if self.closed {
            Err(NextEx_BadState)
        } else {
            unsafe {
                let mut pkthdr_ptr: *mut Struct_pcap_pkthdr = std::intrinsics::uninit();
                
                // const u_char*
                let mut pkt_data_ptr: *mut u8 = std::intrinsics::uninit();

                let result = pcap_next_ex(self.dev, &mut pkthdr_ptr, &mut(pkt_data_ptr as *u8));

                let pkt_len: uint = (*pkthdr_ptr).len as uint;

                println!("{}", pkt_len);

                match result {
                    -2 => { Err(NextEx_EndOfCaptureFile) }
                    -1 => { Err(NextEx_ReadError) } // call pcap_getErr(NextEx_) or pcap_perror() (ret Result instead)
                    0 => { Err(NextEx_Timeout) }
                    1 => {
                        if pkt_len == 0 {
                            println!("ignoring zero length packet"); 
                            Err(Unknown)
                        } else {
                            // let payload = Vec::from_buf(pkt_data_ptr, pkt_len);
                            println!("payload");
                            
                            let payload: Vec<u8> = Vec::from_raw_parts(pkt_len, pkt_len, pkt_data_ptr);
                            println!("payload2");
                            println!("{}", payload);
                            
                            let payload = payload.as_slice().to_owned();
                            println!("payload3");
                            println!("{}", payload);

                            let pkt = PcapPacket{
                                timestamp: (*pkthdr_ptr).ts,
                                len: pkt_len,
                                // is this the best way?
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
            let data1 = pkt.as_ptr() as *u8;
            let size1 = pkt.len() as i32;
            let result = pcap_sendpacket(self.dev, data1, size1);
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
            pcap_close(self.dev);
        }
    }
}
