#[feature(globs)];

#[link(name="pcapfe", vers="0.0.1")];

extern mod std;

use std::cast;
use std::io::net::ip;
use std::io::util;
use std::libc::{c_uint,c_schar};
use std::ptr;
use std::str;
use std::vec;

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
    Type:       EthernetType,
}

pub enum EthernetType {
    EthernetType_IPv4,
    EthernetType_IPv6,
    EthernetType_Unknown,
}

pub struct Ipv4Header {
    Version:     uint,
    Ihl:         uint,
    Tos:         uint,
    Length:      uint,
    Id:          uint,
    Flags:       uint,
    FragOffset:  uint,
    Ttl:         uint,
    Protocol:    InternetProtocolNumbers,
    Checksum:    uint,
    SrcIp:       ip::IpAddr,
    DstIp:       ip::IpAddr,
}

pub enum InternetProtocolNumbers {
    ICMP = 1,
    TCP = 6,
    UserDatagram = 17,
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

pub enum DecodedPacket<'r> {
    InvalidPacket,
    EthernetPacket(EthernetHeader, &'r [u8]),
    IpPacket(EthernetHeader, Ipv4Header, &'r [u8]),
    TcpPacket(EthernetHeader, Ipv4Header, TcpHeader, &'r [u8]),
    UdpPacket(EthernetHeader, Ipv4Header, UdpHeader, &'r [u8]),
}

pub fn decode_ethernet_header(header_plus_payload: &[u8]) -> Option<(EthernetHeader, uint)> {
    // TODO: Check size

    let dst_mac = mac_from_slice(header_plus_payload.slice(0, 6));
    let src_mac = mac_from_slice(header_plus_payload.slice(6, 12));
    //let type_ = unsafe { header_plus_payload.slice(13, 14).to_owned() as uint }; // TODO: Fix
    let type_ = 0x0400;
    let type_ = match type_ {
        0x0400 => { EthernetType_IPv4 }
        0x0800 => { EthernetType_IPv6 }
        _ => { EthernetType_Unknown }
    };
    let ether_hdr = EthernetHeader{
        DstMac: dst_mac,
        SrcMac: src_mac,
        Type: type_,
    };
    Some((ether_hdr, 14))
}

pub fn decode_ipv4_header(header_plus_payload: &[u8]) -> Option<(Ipv4Header, uint)> {
    // TODO: Check size

    Some((Ipv4Header{
        Version:     80,
        Ihl:         80,
        Tos:         80,
        Length:      80,
        Id:          80,
        Flags:       80,
        FragOffset:  80,
        Ttl:         80,
        Protocol:    TCP,
        Checksum:    80,
        SrcIp:       ip::Ipv4Addr(127, 0, 0, 1),
        DstIp:       ip::Ipv4Addr(127, 0, 0, 1),
        // copy the remaining payload pointer here?
        // is that valuable?
        // honestly, might be nicer, in case you match a TCP Packet, but want the
        // Ethernet header and the rest of the raw bytes
        // ... otherwise, there really wouldn't be a way to access that easily through my API...
    },
    20))
    // length of (the ipv4 header or the whole rest of it, I'm not sure, check this)
}

pub fn decode_tcp_header(header_plus_payload: &[u8]) -> Option<(TcpHeader, uint)> {
    // TODO: Check size

    Some((TcpHeader{
        SrcPort:     80,
        DstPort:     80,
        Seq:         80,
        Ack:         80,
        DataOffset:  80,
        Flags:       80,
        Window:      80,
        Checksum:    80,
        Urgent:      80,
    },
    20))
}

pub fn decode_udp_header(header_plus_payload: &[u8]) -> Option<(UdpHeader, uint)> {
    // TODO: Check size

    Some((UdpHeader{
        SrcPort:  80,
        DstPort:  80,
        Length:   80,
        Checksum: 90,
    },
    8))
}

pub fn pp(p: &[u8]) {
    let p2 = p.map(|&e| if e > 31 && e < 127 { e } else { '.' as u8 });
    println!("print ascii-mapped bytes: {:?}", p2);
    let temp_payload = unsafe { str::from_utf8_owned(p2); };
    println!("print utf8 bytes        : {:?}", temp_payload); // why does this not print properly here
    // even thought the same technique seems to work inline elsewhere and the p2 seems to contain the correct bytes...
}

pub fn DecodePacket<'r>(pkt: &'r PcapPacket) -> DecodedPacket<'r> {
    let SIZE_ETHERNET_HEADER = 14;
    let SIZE_IP_HEADER_MIN = 20;
    let SIZE_IP_HEADER_MAX = 20; // TODO set this and use it
    let SIZE_TCP_HEADER = 1; // FIX
    let SIZE_UDP_HEADER = 1; // FIX

    let mut payload: &'r [u8] = pkt.payload;
    let mut size = pkt.len;

    let c = 0;

    match decode_ethernet_header(payload) {
        Some((ether_hdr, ether_hdr_len)) => {
            payload = payload.slice_from(ether_hdr_len-c);
            match ether_hdr.Type {
                IPv4 => match decode_ipv4_header(payload) {
                    Some((ip_hdr, ip_hdr_len)) => {
                        payload = payload.slice_from(ip_hdr_len-c);
                        match ip_hdr.Protocol {
                            TCP => {
                                match decode_tcp_header(payload) {
                                    Some((tcp_hdr, tcp_hdr_len)) => {
                                        payload = payload.slice_from(tcp_hdr_len-c);
                                        TcpPacket(ether_hdr, ip_hdr, tcp_hdr, payload)
                                    }
                                    None => { InvalidPacket }
                                }
                            }
                            UserDatagram => {
                                match decode_udp_header(payload) {
                                    Some((udp_hdr, udp_hdr_len)) => {
                                        payload = payload.slice_from(udp_hdr_len-c);
                                        UdpPacket(ether_hdr, ip_hdr, udp_hdr, payload)
                                    }
                                    None => { InvalidPacket } // could let it fall through? does it matter?
                                }
                            }
                            _ => { InvalidPacket }
                        }
                    },
                    None => { InvalidPacket }
                },
                
                /*
                IPv6 => match decode_ipv6_header(payload) {

                },
                */
                
                /*
                _ => { return InvalidPacket; } // should I _have_ to uncomment this "dead" code.
                // it won't be dead when I add new types
                // that means adding new types to the enum in the future will break code.
                // that's probably okay?
                */
            }
        }
        None => {
            InvalidPacket // change the return type to opt or result
        }
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

    /*
    pub fn Inject(&self, pkt: DecodedPacket) -> Result<(), ()> {
        // pcap_inject(arg1: *mut pcap_t, arg2: *c_void, arg3: size_t) -> c_int;
        match pkt {
            TcpPacket(ehdr, ihdr, thdr, pkt) => {
                println!("tcp, {:?}", pkt);
                let data = pkt.bytes();
                let result = pcap_inject(self.pcap_dev, data, data.length);
                match result {
                    -1 => {}
                    0 => {}
                    1 => {}
                }
            }
            _ => {

            }
        };
        Ok(())
    }
    */

    // Should this be impl Drop for PcapDevice?
    pub fn Close(&mut self) {
        unsafe {
            self.closed = true;
            pcap_close(self.pcap_dev);
        }
    }
}