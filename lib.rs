#[crate_id="pcapfe"];
#[crate_type="lib"];
#[desc = "A Rust package wrapping libpcap and providing packet decoding"];
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

pub static SIZE_ETHERNET_HEADER: uint = 14;
pub static SIZE_IP_HEADER_MIN: uint = 20;
pub static SIZE_IP_HEADER_MAX: uint = 80;
pub static SIZE_TCP_HEADER: uint = 1;
pub static SIZE_UDP_HEADER: uint = 8;

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

pub struct EthernetHeader {
    DstMac:     ~[u8],
    SrcMac:     ~[u8],
    Ethertype:  Ethertype,
}
impl EthernetHeader {
    pub fn len(&self) -> uint { 14 }
    pub fn as_bytes(&self) -> ~[u8] {
        let mut res: ~[u8] = ~[];
        res = std::vec::append(res, self.DstMac);
        res = std::vec::append(res, self.SrcMac);
        res = std::vec::append_one(res, (self.Ethertype as u16 >> 8) as u8) ;
        res = std::vec::append_one(res, self.Ethertype as u8);
        res
    }
}

#[deriving(Eq)]
pub enum Ethertype {
    Ethertype_IP = 0x0800,
    Ethertype_ARP = 0x0806,
    Ethertype_VLAN = 0x8100,
    Ethertype_Unknown = 0x0000,
}

pub struct Ipv4Header {
    Version:      u8,
    Ihl:          u8,
    DiffServices: u8,
    Ecn:          u8,
    TotalLength:  u16,
    Id:           u16,
    Flags:        u8,
    FragOffset:   u16,
    Ttl:          u8,
    Protocol:     InternetProtocolNumbers,
    Checksum:     u16,
    SrcIp:        ip::IpAddr,
    DstIp:        ip::IpAddr,
    Options:     ~[u8],
}
impl Ipv4Header {
    pub fn len(&self) -> uint { self.Ihl as uint *4 }
    pub fn as_bytes(&self) -> ~[u8] {
        let mut res: ~[u8] = ~[];
        res = std::vec::append_one(res, ((self.Version as u8) << 4) | self.Ihl as u8);
        res = std::vec::append_one(res, (self.DiffServices as u8) << 6 | (self.Ecn) as u8);
        res = std::vec::append_one(res, (self.TotalLength >> 8) as u8);
        res = std::vec::append_one(res, self.TotalLength as u8);
        res = std::vec::append_one(res, (self.Id >> 8) as u8);
        res = std::vec::append_one(res, self.Id as u8);

        res = std::vec::append_one(res, ((self.Flags as u8) << 5) | ((self.FragOffset >> 14) as u8));
        res = std::vec::append_one(res, self.FragOffset as u8);
        res = std::vec::append_one(res, self.Ttl as u8);
        res = std::vec::append_one(res, self.Protocol as u8);
        res = std::vec::append_one(res, (self.Checksum >> 8) as u8);
        res = std::vec::append_one(res, self.Checksum as u8);

        match (self.SrcIp, self.DstIp) {
            (Ipv4Addr(a,b,c,d), Ipv4Addr(g,h,i,j)) => {
                res = std::vec::append(res, [a,b,c,d,g,h,i,j]);
            }
            (_, _) => { fail!(); }
        }

        res = std::vec::append(res, self.Options);

        res
    }
}

pub struct Ipv6Header {
    Temp:        uint,
}

#[deriving(Eq)]
pub enum InternetProtocolNumbers {
    ICMP = 1,
    TCP = 6,
    UserDatagram = 17,
}

#[deriving(Eq)]
pub struct TcpFlags {
    ns:  bool,
    cwr: bool,
    ece: bool,
    urg: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,
}

// cast these to uints?
pub struct TcpHeader {
    SrcPort:     ip::Port,
    DstPort:     ip::Port,
    SeqNum:      u32,
    AckNum:      u32,
    DataOffset:  u8,
    Flags:       TcpFlags,
    WindowSize:  u16,
    Checksum:    u16,
    UrgentPtr:   u16,
    Options:     ~[u8],
}
impl TcpHeader {
    pub fn len(&self) -> uint { self.DataOffset as uint *4 }
    pub fn as_bytes(&self) -> ~[u8] {
        let mut res: ~[u8] = ~[];

        res = std::vec::append_one(res, ((self.SrcPort as u16) >> 8) as u8);
        res = std::vec::append_one(res, self.SrcPort as u8);
        res = std::vec::append_one(res, ((self.DstPort as u16) >> 8) as u8);
        res = std::vec::append_one(res, self.DstPort as u8);

        res = std::vec::append_one(res, ((self.SeqNum as u32) >> 24) as u8);
        res = std::vec::append_one(res, ((self.SeqNum as u32) >> 16) as u8);
        res = std::vec::append_one(res, ((self.SeqNum as u32) >> 8) as u8);
        res = std::vec::append_one(res, ((self.SeqNum as u32) >> 0) as u8);
        
        res = std::vec::append_one(res, ((self.AckNum as u32) >> 24) as u8);
        res = std::vec::append_one(res, ((self.AckNum as u32) >> 16) as u8);
        res = std::vec::append_one(res, ((self.AckNum as u32) >> 8) as u8);
        res = std::vec::append_one(res, ((self.AckNum as u32) >> 0) as u8);
        
        let flags_byte = self.DataOffset << 4 | if self.Flags.ns { 0b00000001 } else { 0 };

        let mut flags_byte2 = 0;        
        if self.Flags.cwr { flags_byte2 += 0b10000000 };
        if self.Flags.ece { flags_byte2 += 0b01000000 };
        if self.Flags.urg { flags_byte2 += 0b00100000 };
        if self.Flags.ack { flags_byte2 += 0b00010000 };
        if self.Flags.psh { flags_byte2 += 0b00001000 };
        if self.Flags.rst { flags_byte2 += 0b00000100 };
        if self.Flags.syn { flags_byte2 += 0b00000010 };
        if self.Flags.fin { flags_byte2 += 0b00000001 };

        res = std::vec::append_one(res, flags_byte as u8);
        res = std::vec::append_one(res, flags_byte2 as u8);

        res = std::vec::append_one(res, (self.WindowSize >> 8) as u8);
        res = std::vec::append_one(res, (self.WindowSize >> 0) as u8);
        res = std::vec::append_one(res, (self.Checksum >> 8) as u8);
        res = std::vec::append_one(res, (self.Checksum >> 0) as u8);
        res = std::vec::append_one(res, (self.UrgentPtr >> 8) as u8);
        res = std::vec::append_one(res, (self.UrgentPtr >> 0) as u8);

        res = std::vec::append(res, self.Options);

        res
    }
}

pub struct UdpHeader {
    SrcPort:     ip::Port,
    DstPort:     ip::Port,
    Length:      uint,
    Checksum:    uint,
}
impl UdpHeader {
    pub fn len(&self) -> uint { 8 }
    pub fn as_bytes(&self) -> ~[u8] {
        //let res: ~[u8] = ~[u8, ..8];
        let mut res: ~[u8] = ~[];
        res = std::vec::append_one(res, ((self.SrcPort as u16) >> 8) as u8);
        res = std::vec::append_one(res, self.SrcPort as u8);
        res = std::vec::append_one(res, ((self.DstPort as u16) >> 8) as u8);
        res = std::vec::append_one(res, self.DstPort as u8);
        res = std::vec::append_one(res, (self.Length >> 8) as u8);
        res = std::vec::append_one(res, self.Length as u8);
        res = std::vec::append_one(res, (self.Checksum >> 8) as u8);
        res = std::vec::append_one(res, self.Checksum as u8);

        res
    }
}

pub enum DecodedPacket<'r> {
    InvalidPacket,
    EthernetPacket(EthernetHeader, &'r [u8]),
    Ipv4Packet(EthernetHeader, Ipv4Header, &'r [u8]),
    TcpPacket(EthernetHeader, Ipv4Header, TcpHeader, &'r [u8]),
    UdpPacket(EthernetHeader, Ipv4Header, UdpHeader, &'r [u8]),
}

pub fn decode_ethernet_header(h: &[u8]) -> Option<EthernetHeader> {
    if h.len() < 14 {
        return None
    }
    
    let dst_mac = h.slice(0, 6).to_owned();
    let src_mac = h.slice(6, 12).to_owned();
    let ethertype: u16 = h[12] as u16 << 8 | h[13] as u16;
    let ethertype = match ethertype {
        0x0800 => { Ethertype_IP }
        0x0806 => { Ethertype_ARP }
        0x8100 => { Ethertype_VLAN }
        _ => { Ethertype_Unknown }
    };

    Some(EthernetHeader{
        DstMac: dst_mac,
        SrcMac: src_mac,
        Ethertype: ethertype,
    })
}

pub fn decode_ipv4_header(h: &[u8]) -> Option<Ipv4Header> {
    if h.len() < 20 {
        return None
    }

    let version = (h[0] & 0b11110000) >> 4;
    let ihl = h[0] & 0b00001111;

    let dscp = h[1] >> 2;
    let ecn = h[1] & 0b00000011;

    let total_len: u16 = h[2] as u16 << 8 | h[3] as u16;
    let id: u16 = h[4] as u16 << 8 | h[5] as u16;

    let flags = (h[6] >> 5) & 0b00000111;

    let frag_offset: u16 = h[6] as u16 << 8 | h[7] as u16;
    let frag_offset = frag_offset & 0b0001111111111111;

    let ttl = h[8];
    let proto = h[9];

    let checksum: u16 = h[10] as u16 << 8 | h[11] as u16;

    let src_ip = Ipv4Addr(h[12], h[13], h[14], h[15]);
    let dst_ip = Ipv4Addr(h[16], h[17], h[18], h[19]);


    if ihl > 15 {
        return None
    }
    
    let options = h.slice(20, 20+(4*(ihl as uint - 5))).to_owned();

    Some(Ipv4Header{
        Version:      version,
        Ihl:          ihl,
        DiffServices: dscp,
        Ecn:          ecn,
        TotalLength:  total_len,
        Id:           id,
        Flags:        flags,
        FragOffset:   frag_offset,
        Ttl:          ttl,
        Protocol:     match(proto) { 0x06 => { TCP }, _ => { UserDatagram } },
        Checksum:     checksum,
        SrcIp:        src_ip,
        DstIp:        dst_ip,
        Options:      options,
    })
}

pub fn decode_ipv6_header(h: &[u8]) -> Option<Ipv6Header> {
    None
}

pub fn decode_tcp_header(h: &[u8]) -> Option<TcpHeader> {
    if h.len() < 20 {
        return None
    }

    let src_port: u16 = h[0] as u16 << 8 | h[1] as u16;
    let dst_port: u16 = h[2] as u16 << 8 | h[3] as u16;

    let seq_num: u32 = h[4] as u32 << 24 | h[5] as u32 << 16 | h[6] as u32 << 8 | h[7] as u32;
    let ack_num: u32 = h[8] as u32 << 24 | h[9] as u32 << 16 | h[10] as u32 << 8 | h[11] as u32;

    let data_offset = h[12] >> 4;

    let  ns: bool = (h[12] & 0b00000001) != 0;
    let cwr: bool = (h[13] >> 7 & 0b00000001) != 0;
    let ece: bool = (h[13] >> 6 & 0b00000001) != 0;
    let urg: bool = (h[13] >> 5 & 0b00000001) != 0;
    let ack: bool = (h[13] >> 4 & 0b00000001) != 0;
    let psh: bool = (h[13] >> 3 & 0b00000001) != 0;
    let rst: bool = (h[13] >> 2 & 0b00000001) != 0;
    let syn: bool = (h[13] >> 1 & 0b00000001) != 0;
    let fin: bool = (h[13] >> 0 & 0b00000001) != 0;

    let window_size: u16 = h[14] as u16 << 8 | h[15] as u16;
    let checksum: u16 = h[16] as u16 << 8 | h[17] as u16;
    let urgent_ptr: u16 = h[18] as u16 << 8 | h[19] as u16;

    let options: ~[u8] = h.slice(20, (data_offset as uint)*4).to_owned();

    Some(TcpHeader{
        SrcPort:     src_port,
        DstPort:     dst_port,
        SeqNum:      seq_num,
        AckNum:      ack_num,
        DataOffset:  data_offset,
        Flags:       TcpFlags{
            ns: ns,
            cwr: cwr,
            ece: ece,
            urg: urg,
            ack: ack,
            psh: psh,
            rst: rst,
            syn: syn,
            fin: fin,
        },
        WindowSize:  window_size,
        Checksum:    checksum,
        UrgentPtr:   urgent_ptr,
        Options:     options,
    })
}

pub fn decode_udp_header(h: &[u8]) -> Option<UdpHeader> {
    if h.len() < 8 {
        return None
    }
    let src_port: u16 = h[0] as u16 << 8 | h[1] as u16;
    let dst_port: u16 = h[2] as u16 << 8 | h[3] as u16;
    let length: u16   = h[4] as u16 << 8 | h[5] as u16;
    let checksum: u16 = h[6] as u16 << 8 | h[7] as u16;

    Some(UdpHeader{
        SrcPort:  src_port as ip::Port,
        DstPort:  dst_port as ip::Port,
        Length:   length   as uint,
        Checksum: checksum as uint,
    })
}

pub fn prettystr(p: &[u8]) -> ~str {
    let p = p.map(|&e| if e > 31 && e < 127 { e } else { '.' as u8 });
    str::from_utf8_owned(p)
}

pub fn DecodePacket<'r>(payload: &'r [u8]) -> DecodedPacket<'r> {
    let mut payload = payload;

    match decode_ethernet_header(payload) {
        Some(ether_hdr) => {
            payload = payload.slice_from(ether_hdr.len());
            match ether_hdr.Ethertype {
                Ethertype_IP => match decode_ipv4_header(payload) {
                    Some(ip_hdr) => {
                        payload = payload.slice_from(ip_hdr.len());
                        match ip_hdr.Protocol {
                            TCP => match decode_tcp_header(payload) {
                                Some(tcp_hdr) => {
                                    payload = payload.slice_from(tcp_hdr.len());
                                    TcpPacket(ether_hdr, ip_hdr, tcp_hdr, payload)
                                }
                                None => { InvalidPacket }
                            },
                            UserDatagram => match decode_udp_header(payload) {
                                Some(udp_hdr) => {
                                    payload = payload.slice_from(udp_hdr.len());
                                    UdpPacket(ether_hdr, ip_hdr, udp_hdr, payload)
                                }
                                None => { InvalidPacket } // could let it fall through? does it matter?
                            },
                            _ => { InvalidPacket }
                        }
                    },
                    None => { InvalidPacket }
                },
                _ => { InvalidPacket }
            }
        },
        None => {
            InvalidPacket // change the return type to opt or result
        }
    }
}

pub struct PcapDevice {
    pcap_dev: *mut pcap_t,
    closed: bool
}

pub struct PcapPacket {
    timestamp: Struct_timeval,
    len: uint,
    payload: ~[u8]
}

pub fn PcapOpenDevice(dev: &str) -> Result<PcapDevice, ~str> {
    PcapOpenDeviceAdv(dev, 65536, 0, 1000)
}

pub fn PcapOpenDeviceAdv(dev: &str, size: int, flag: int, mtu: int) -> Result<PcapDevice, ~str> {
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
    pub fn SetFilter(&self, dev: &str, filter_str: &str) -> Result<(), PcapError> {
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

    pub fn NextPacketEx(&self) -> Result<PcapPacket, PcapError> {
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
                            // HELP: does that copy? pkt_data_ptr's location is reused
                            
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

    pub fn Inject(&self, pkt: DecodedPacket) -> Option<uint> {
        unsafe {
            let mut data: ~[u8];
            match pkt {
                EthernetPacket(eth_hdr, payload) => {
                    data = eth_hdr.as_bytes();
                    data = std::vec::append(data, payload);
                }
                Ipv4Packet(eth_hdr, ip_hdr, payload) => {
                    data = eth_hdr.as_bytes();
                    data = std::vec::append(data, ip_hdr.as_bytes());
                    data = std::vec::append(data, payload);
                }
                TcpPacket(eth_hdr, ip_hdr, tcp_hdr, payload) => {
                    data = eth_hdr.as_bytes();
                    data = std::vec::append(data, ip_hdr.as_bytes());
                    data = std::vec::append(data, tcp_hdr.as_bytes());
                    data = std::vec::append(data, payload);
                }
                UdpPacket(eth_hdr, ip_hdr, udp_hdr, payload) => {
                    data = eth_hdr.as_bytes();
                    data = std::vec::append(data, ip_hdr.as_bytes());
                    data = std::vec::append(data, udp_hdr.as_bytes());
                    data = std::vec::append(data, payload);
                }
                InvalidPacket => { fail!(); }
            };
            let data1 = data.as_ptr() as *c_void;
            let size1 = data.len() as u64;
            let result = pcap_inject(self.pcap_dev, data1, size1);
            match result {
                -1 => { None }
                n => { Some(n as uint) } // HELP: not safe if negative (block w/ negative range in match [how?])
            }
        }
    }

    // HELP: Should this be impl Drop for PcapDevice?
    pub fn Close(&mut self) {
        unsafe {
            self.closed = true;
            pcap_close(self.pcap_dev);
        }
    }
}