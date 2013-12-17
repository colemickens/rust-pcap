#[feature(globs)];

#[link(name="pcapfe", vers="0.0.1")];

extern mod std;

use std::libc::{c_uint,c_schar};
use std::{ptr,vec};

use std::cast;

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
    DeviceClosed, // FIX: this is a dup of the above error. Consolidate these enums?
    CompileError,
    SetError
}

pub struct EthernetHeader {
    DestMac:    [u8, ..6],
    SrcMac:     [u8, ..6],
}

pub struct ArpHeader {
    Addrtype:        uint,
    Protocol:        uint,
    HwAddressSize:   uint,
    ProtAddressSize: uint,
    Operation:       uint,
    SourceHwAddr:    [u8, ..6],
    SourceProtAddr:  [u8, ..6],
    DestHwAddr:      [u8, ..6],
    DestProtAddr:    [u8, ..6],
}

pub struct IpHeader {
    Version:     uint,
    Ihl:         uint,
    Tos:         uint,
    Length:      uint,
    Id:          uint,
    Flags:       uint,
    FragOffset:  uint,
    Ttl:         uint,
    Protocol:    uint,
    Checksum:    uint,
    SrcIp:       [u8, ..6],
    DstIp:       [u8, ..6],
}

pub struct TcpHeader {
    SrcPort:     uint,
    DestPort:    uint,
    Seq:         uint,
    Ack:         uint,
    DataOffset:  uint,
    Flags:       uint,
    Window:      uint,
    Checksum:    uint,
    Urgent:      uint,
    Data:        uint,
}

pub struct UdpHeader {
    SrcPort:     uint,
    DestPort:    uint,
    Length:      uint,
    Checksum:    uint,
}

pub enum DecodedPacket {
    EthernetPacket(EthernetHeader, ~[u8]),
    ArpPacket(EthernetHeader, ArpHeader, ~[u8]),
    IpPacket(EthernetHeader, IpHeader, ~[u8]),
    TcpPacket(EthernetHeader, IpHeader, TcpHeader, ~[u8]),
    UdpPacket(EthernetHeader, IpHeader, UdpHeader, ~[u8]),
}

pub fn DecodePacket(pkt: &PcapPacket) -> DecodedPacket {
    EthernetPacket(
        EthernetHeader{
            DestMac: pkt.payload.slice(0,6),
            SrcMac: pkt.payload.slide(6,12)
        },
        pkt.payload.slice(12)
    )
}

// pcap wrapper

pub struct PcapDevice {
    pcap_dev: *mut pcap_t,
    closed: bool
}

pub struct PcapPacket {
    timestamp: Struct_timeval,
    len: uint,
    payload: ~[u8]
}

pub fn PcapOpenDevice(dev: &str) -> Option<PcapDevice> {
    PcapOpenDeviceAdv(dev, 65536, 0, 1000)
}

pub fn PcapOpenDeviceAdv(dev: &str, size: int, flag: int, mtu: int) -> Option<PcapDevice> {
    unsafe {
        let mut errbuf: ~[c_schar] = vec::with_capacity(256);
        let c_dev = dev.to_c_str().unwrap();
        let handle = pcap_open_live(c_dev, size as i32, flag as i32, mtu as i32, errbuf.as_mut_ptr());
        // should probably do something with error buffer?
        if handle == ptr::mut_null() {
            None
        } else {
            let pd: PcapDevice = PcapDevice { pcap_dev: handle, closed: false };
            Some(pd)
        }
    }
}

impl PcapDevice {
    pub fn SetFilter(&self, dev: &str, filter_str: &str) -> Result<(), PcapFilterError> {
        unsafe {
            if self.closed {
                return Err(DeviceClosed)
            }
            let mut errbuf: ~[c_schar] = vec::with_capacity(256);
            let mut netp: c_uint = 0;
            let mut maskp: c_uint = 0;
            let mut filter_program: Struct_bpf_program = std::unstable::intrinsics::uninit();

            let c_dev = dev.to_c_str().unwrap();
            let c_filter_str = filter_str.to_c_str().unwrap();
            
            pcap_lookupnet(c_dev, &mut netp, &mut maskp, errbuf.as_mut_ptr());
            let res = pcap_compile(self.pcap_dev, &mut filter_program, c_filter_str, 0, netp);
            if res != 0 {
                Err(CompileError)
            } else {
                let res = pcap_setfilter(self.pcap_dev, &mut filter_program);
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
            Err(BadState)
        } else {
            unsafe {
                let mut pkthdr_ptr: *mut Struct_pcap_pkthdr = std::unstable::intrinsics::uninit();
                let mut pkt_data_ptr: *u8 = std::unstable::intrinsics::uninit();

                let result = pcap_next_ex( self.pcap_dev, &mut pkthdr_ptr, &mut pkt_data_ptr);

                let pkt_len: uint = (*pkthdr_ptr).len as uint;
                match result {
                    -2 => { Err(EndOfCaptureFile) }
                    -1 => { Err(ReadError) } // call pcap_geterr() or pcap_perror()
                    0 => { Err(Timeout) }
                    1 => {
                        if pkt_len == 0 {
                            println!("ignoring zero length packet"); 
                            Err(Unknown)
                        } else {
                            let payload = std::vec::from_buf(pkt_data_ptr, pkt_len); // does this copy? pkt_data_ptr's location is reused
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

    // Should this be impl Drop for PcapDevice?
    pub fn Close(&mut self) {
        unsafe {
            self.closed = true;
            pcap_close(self.pcap_dev);
        }
    }
}