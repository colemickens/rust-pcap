#[feature(globs)];

#[link(name="pcapfe", vers="0.0.1")];

extern mod std;

use std::libc::{c_uint,c_schar};
use std::{ptr,vec};
use std::io::net::ip;

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

pub struct MacAddress {
    // there must be a better way!
    Address: [u8, ..6]
}

pub fn mac_from_slice(sl: &[u8]) -> MacAddress {
    MacAddress{
        Address: [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 ],
    }
}

pub struct EthernetHeader {
    DstMac:     MacAddress,
    SrcMac:     MacAddress,
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
    SrcIp:       ip::IpAddr,
    DstIp:       ip::IpAddr,
}

pub struct TcpHeader {
    SrcPort:     ip::Port,
    DstPort:     ip::Port,
    Seq:         uint,
    Ack:         uint,
    DataOffset:  uint,
    Flags:       uint,
    Window:      uint,
    Checksum:    uint,
    Urgent:      uint,
}

pub struct UdpHeader {
    SrcPort:     ip::Port,
    DstPort:     ip::Port,
    Length:      uint,
    Checksum:    uint,
}

pub enum DecodedPacket {
    InvalidPacket,
    EthernetPacket(EthernetHeader, &[u8]),
    IpPacket(EthernetHeader, IpHeader, &[u8]),
    TcpPacket(EthernetHeader, IpHeader, TcpHeader, &[u8]),
    UdpPacket(EthernetHeader, IpHeader, UdpHeader, &[u8]),
}


const SIZE_ETHERNET_HEADER = 14;
const SIZE_IP_HEADER_MIN = 20;
const SIZE_IP_HEADER_MAX = 20; // TODO set this and use it
const SIZE TCP_HEADER = ;
const SIZE UDP_HEADER = ;

pub fn DecodePacket(pkt: &PcapPacket) -> DecodedPacket {
    let payload: &[u8];
    let mut size = pkt.length;

    if size > SIZE_ETHERNET_HEADER { // make these consts
        size = size - SIZE_ETHERNET_HEADER;
        let ethernet_hdr = decode_ethernet_header();

        if size > SIZE_IP_HEADER_MIN {
            let ip_hdr = decode_ip_header();
            if ip_hdr.total_length > SIZE_IP_HEADER_MAX {
                InvalidPacket // give better feedback somehow?
            }
            size = size - ip_hdr.total_length;
            match ip_hdr.protocol {
                tcp: {
                    if size > SIZE_TCP_HEADER {
                        let tcp_hdr = decode_tcp_header();
                        TcpPacket(ethernet_hdr, ip_hdr, tcp_hdr, payload)
                    }
                }
                udp: {
                    if size > SIZE_UDP_HEADER {
                        let udp_hdr = decode_tcp_header();
                        TcpPacket(ethernet_hdr, ip_hdr, udp_hdr, payload)
                    }
                }
                _: {
                    // ignore these as unsupported for now, esp INIP
                    InvalidPacket
                }
            }
        } else {
            EthernetPacket(ethernet_hdr, payload)
        }
    } else {
        InvalidPacket
    }    
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