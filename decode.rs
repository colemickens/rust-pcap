#[crate_id="pktdecode"];
#[crate_type="lib"];
#[desc = "A Rust package providing packet decoding"];
#[license = "MIT"];

#[feature(globs)];

extern mod std;

use std::io::net::ip;
use std::io::net::ip::Ipv4Addr;

pub struct EthernetHeader {
    dst_mac:    ~[u8],
    src_mac:    ~[u8],
    ethertype:  Ethertype,
}
impl EthernetHeader {
    pub fn len(&self) -> uint { 14 }
    pub fn as_bytes(&self) -> ~[u8] {
        let mut res: ~[u8] = ~[];
        res.push_all(self.dst_mac);
        res.push_all(self.src_mac);
        res.push( (self.ethertype as u16 >> 8) as u8  );
        res.push( self.ethertype as u8 );
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
    version:       u8,
    ihl:           u8,
    diff_services: u8,
    ecn:           u8,
    total_len:     u16,
    id:            u16,
    flags:         u8,
    frag_offset:   u16,
    ttl:           u8,
    protocol:      InternetprotocolNumbers,
    checksum:      u16,
    src_ip:        ip::IpAddr,
    dst_ip:        ip::IpAddr,
    options:       ~[u8],
}
impl Ipv4Header {
    pub fn len(&self) -> uint { self.ihl as uint *4 }
    pub fn as_bytes(&self) -> ~[u8] {
        match (self.src_ip, self.dst_ip) {
            (Ipv4Addr(a,b,c,d), Ipv4Addr(g,h,i,j)) => {
                let mut res: ~[u8] = ~[
                    self.version << 4 | self.ihl,
                    self.diff_services << 6 | (self.ecn & 0b00000011),
                    (self.total_len >> 8) as u8,
                    self.total_len as u8,
                    (self.id >> 8) as u8,
                    self.id as u8,

                    (self.flags << 5) | ((self.frag_offset >> 14) as u8),
                    self.frag_offset as u8,
                    self.ttl,
                    self.protocol as u8,
                    (self.checksum >> 8) as u8,
                    self.checksum as u8,
                    a, b, c, d, g, h, i, j
                ];
                res.push_all(self.options);
                return res
            }
            (_, _) => { fail!(); }
        }
    }
}

pub struct Ipv6Header {
    temp:        uint,
}

#[deriving(Eq)]
pub enum InternetprotocolNumbers {
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

pub struct TcpHeader {
    src_port:     ip::Port,
    dst_port:     ip::Port,
    seq_num:      u32,
    ack_num:      u32,
    data_offset:  u8,
    flags:        TcpFlags,
    window_size:  u16,
    checksum:     u16,
    urgent_ptr:   u16,
    options:      ~[u8],
}
impl TcpHeader {
    pub fn len(&self) -> uint { self.data_offset as uint *4 }
    pub fn as_bytes(&self) -> ~[u8] {
        let flags_byte = self.data_offset << 4 | if self.flags.ns { 0b00000001 } else { 0 };

        let mut flags_byte2 = 0;        
        if self.flags.cwr { flags_byte2 += 0b10000000 };
        if self.flags.ece { flags_byte2 += 0b01000000 };
        if self.flags.urg { flags_byte2 += 0b00100000 };
        if self.flags.ack { flags_byte2 += 0b00010000 };
        if self.flags.psh { flags_byte2 += 0b00001000 };
        if self.flags.rst { flags_byte2 += 0b00000100 };
        if self.flags.syn { flags_byte2 += 0b00000010 };
        if self.flags.fin { flags_byte2 += 0b00000001 };

        let mut res: ~[u8] = ~[
            ((self.src_port as u16) >> 8) as u8,
            self.src_port as u8,
            ((self.dst_port as u16) >> 8) as u8,
            self.dst_port as u8,

            ((self.seq_num as u32) >> 24) as u8,
            ((self.seq_num as u32) >> 16) as u8,
            ((self.seq_num as u32) >> 8) as u8,
            ((self.seq_num as u32) >> 0) as u8,
        
            ((self.ack_num as u32) >> 24) as u8,
            ((self.ack_num as u32) >> 16) as u8,
            ((self.ack_num as u32) >> 8) as u8,
            ((self.ack_num as u32) >> 0) as u8,
            
            flags_byte,
            flags_byte2,

            (self.window_size >> 8) as u8,
            (self.window_size >> 0) as u8,
            (self.checksum >> 8) as u8,
            (self.checksum >> 0) as u8,
            (self.urgent_ptr >> 8) as u8,
            (self.urgent_ptr >> 0) as u8,
        ];

        res.push_all(self.options);

        res
    }
}

pub struct UdpHeader {
    src_port:     ip::Port,
    dst_port:     ip::Port,
    length:       u16,
    checksum:     u16,
}
impl UdpHeader {
    pub fn len(&self) -> uint { 8 }
    pub fn as_bytes(&self) -> ~[u8] {
        ~[
            ((self.src_port as u16) >> 8) as u8,
            self.src_port as u8,
            ((self.dst_port as u16) >> 8) as u8,
            self.dst_port as u8,
            (self.length >> 8) as u8,
            self.length as u8,
            (self.checksum >> 8) as u8,
            self.checksum as u8,
        ]
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
        dst_mac:    dst_mac,
        src_mac:    src_mac,
        ethertype:  ethertype,
    })
}

pub fn decode_ipv4_header(h: &[u8]) -> Option<Ipv4Header> {
    if h.len() < 20 {
        return None
    }

    let ihl = h[0] & 0b00001111;

    if ihl > 15 {
        return None
    }

    Some(Ipv4Header{
        version:        (h[0] & 0b11110000) >> 4,
        ihl:            ihl,
        diff_services:  h[1] >> 2,
        ecn:            h[1] & 0b00000011,
        total_len:      h[2] as u16 << 8 | h[3] as u16,
        id:             h[4] as u16 << 8 | h[5] as u16,
        flags:          (h[6] >> 5) & 0b00000111,
        frag_offset:    (h[6] as u16 << 8 | h[7] as u16) & 0b0001111111111111,
        ttl:            h[8],
        protocol:       match(h[9]) { 0x06 => { TCP }, _ => { UserDatagram } },
        checksum:       h[10] as u16 << 8 | h[11] as u16,
        src_ip:         Ipv4Addr(h[12], h[13], h[14], h[15]),
        dst_ip:         Ipv4Addr(h[16], h[17], h[18], h[19]),
        options:        h.slice(20, 20+(4*(ihl as uint - 5))).to_owned(),
    })
}

pub fn decode_ipv6_header(h: &[u8]) -> Option<Ipv6Header> {
    None
}

pub fn decode_tcp_header(h: &[u8]) -> Option<TcpHeader> {
    if h.len() < 20 {
        return None
    }
    let data_offset = h[12] >> 4;

    Some(TcpHeader{
        src_port:     h[0] as u16 << 8 | h[1] as u16,
        dst_port:     h[2] as u16 << 8 | h[3] as u16,
        seq_num:      h[4] as u32 << 24 | h[5] as u32 << 16 | h[6] as u32 << 8 | h[7] as u32,
        ack_num:      h[8] as u32 << 24 | h[9] as u32 << 16 | h[10] as u32 << 8 | h[11] as u32,
        data_offset:  data_offset,
        flags: TcpFlags{
            ns: (h[12] & 0b00000001) != 0,
            cwr: (h[13] >> 7 & 0b00000001) != 0,
            ece: (h[13] >> 6 & 0b00000001) != 0,
            urg: (h[13] >> 5 & 0b00000001) != 0,
            ack: (h[13] >> 4 & 0b00000001) != 0,
            psh: (h[13] >> 3 & 0b00000001) != 0,
            rst: (h[13] >> 2 & 0b00000001) != 0,
            syn: (h[13] >> 1 & 0b00000001) != 0,
            fin: (h[13] >> 0 & 0b00000001) != 0,
        },
        window_size:  h[14] as u16 << 8 | h[15] as u16,
        checksum:     h[16] as u16 << 8 | h[17] as u16,
        urgent_ptr:   h[18] as u16 << 8 | h[19] as u16,
        options:      h.slice(20, (data_offset as uint)*4).to_owned(),
    })
}

pub fn decode_udp_header(h: &[u8]) -> Option<UdpHeader> {
    if h.len() < 8 {
        return None
    }
    Some(UdpHeader{
        src_port:  (h[0] as u16 << 8 | h[1] as u16) as ip::Port,
        dst_port:  (h[2] as u16 << 8 | h[3] as u16) as ip::Port,
        length:   h[4] as u16 << 8 | h[5] as u16,
        checksum: h[6] as u16 << 8 | h[7] as u16,
    })
}

pub fn decode_packet<'r>(payload: &'r [u8]) -> DecodedPacket<'r> {
    let mut payload = payload;

    match decode_ethernet_header(payload) {
        Some(ether_hdr) => {
            payload = payload.slice_from(ether_hdr.len());
            match ether_hdr.ethertype {
                Ethertype_IP => match decode_ipv4_header(payload) {
                    Some(ip_hdr) => {
                        payload = payload.slice_from(ip_hdr.len());
                        match ip_hdr.protocol {
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
