#[feature(globs)];

extern mod pcapfe;

use std::io::net::ip::Ipv4Addr;

use pcapfe::DecodePacket;
use pcapfe::UdpPacket;
use pcapfe::EthernetType;
use pcapfe::InternetProtocolNumbers;
use pcapfe::EthernetType;
use pcapfe::EthernetType::*;

#[test]
fn test_decode_udp_packet() {
    let dns_pkt: &[u8] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x30, 0x85, 0xa9, 0x40, 0x09, 0x35, 0x08, 0x00, 0x45, 0x00, 0x00, 0x31, 0x27, 0x33, 0x40, 0x00, 0x40, 0x11, 0x8f, 0x37, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0xff, 0xbc, 0xad, 0x7e, 0x9c, 0x00, 0x1d, 0xc9, 0xd9, 0x4d, 0x2d, 0x53, 0x45, 0x41, 0x52, 0x43, 0x48, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a];

    // 0000   ff ff ff ff ff ff 30 85 a9 40 09 35 08 00 45 00  ......0..@.5..E.
    // 0010   00 31 27 33 40 00 40 11 8f 37 c0 a8 01 02 c0 a8  .1'3@.@..7......
    // 0020   01 ff bc ad 7e 9c 00 1d c9 d9 4d 2d 53 45 41 52  ....~.....M-SEAR
    // 0030   43 48 20 2a 20 48 54 54 50 2f 31 2e 31 0d 0a     CH * HTTP/1.1..

    // ffffffffffff3085a94009350800450000312733400040118f37c0a80102c0a801ffbcad7e9c001dc9d94d2d534541524348202a20485454502f312e310d0a
    let expected_payload = [0x4d, 0x2d, 0x53, 0x45, 0x41, 0x52, 0x43, 0x48, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a];

    let pkt = DecodePacket(dns_pkt);
    
    match pkt {
    	UdpPacket(eth_hdr, ip_hdr,  udp_hdr,  payload) => {
			println!("{:?}", eth_hdr);
            println!("{:?}", ip_hdr);
            println!("{:?}", udp_hdr);
            println!("{:?}", payload);

            let dst_mac = ~[0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
            let src_mac = ~[0x30, 0x85, 0xa9, 0x40, 0x09, 0x35];
            assert_eq!(eth_hdr.DstMac, dst_mac);
            assert_eq!(eth_hdr.SrcMac, src_mac);
            //assert_eq!(eth_hdr.Kind, EthernetType_IPv4);
            match eth_hdr.Kind {
                EthernetType_IPv4 => { /* good */ }
                //_ => { fail!("wrong kind of ethernet packet"); } // same as below?
            }

            assert_eq!(ip_hdr.Version, 4);
            assert_eq!(ip_hdr.HeaderLength, 20);
            assert_eq!(ip_hdr.DiffServices, 0x00);
            assert_eq!(ip_hdr.TotalLength, 49);
            assert_eq!(ip_hdr.Id, 0x2733);
            assert_eq!(ip_hdr.Flags, 0x02);            
            assert_eq!(ip_hdr.FragOffset, 0);
            assert_eq!(ip_hdr.Ttl, 64);
            //assert_eq!(ip_hdr.Protocol, UserDatagram); // if I can't do this , what am I doing when I "set" it on line 135/136 of lib.rs?
            match ip_hdr.Protocol {
                UserDatagram => {
                    // good
                },/*
                _ => { fail("n"); }

                // is this unreachable because of UdpPacket match... :o  :D
                */
            }
            assert_eq!(ip_hdr.Checksum, 0x8f37);
            assert_eq!(ip_hdr.SrcIp, Ipv4Addr(192, 168, 1, 2));
            assert_eq!(ip_hdr.DstIp, Ipv4Addr(192, 168, 1, 255));
            
            assert_eq!(udp_hdr.SrcPort, 48301);
            assert_eq!(udp_hdr.DstPort, 32412);
            assert_eq!(udp_hdr.Length, 29);
            assert_eq!(udp_hdr.Checksum, 0x0c9d9);
            
            assert_eq!(payload.len(), 21);
            assert_eq!(payload, expected_payload);
    	}, 
    	_ => { fail!("wrong packet type to start out with"); }
    }
} 