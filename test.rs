extern mod pcapfe;

use pcapfe::DecodePacket;
use pcapfe::UdpPacket;

#[test]
fn test_decode_udp_packet() {
    let dns_pkt: &[u8] = [ 0x9c, 0x2a, 0x70, 0x66, 0x92, 0xe3, 0xe0, 0x91, 0xf5, 0xe3, 0x07, 0xbe, 0x08, 0x00, 0x45, 0x00, 0x00, 0x4d, 0x4e, 0xeb, 0x40, 0x00, 0xf8, 0x11, 0x2c, 0x71, 0x41, 0x20, 0x05, 0x6f, 0xc0, 0xa8, 0x00, 0x0c, 0x00, 0x35, 0xde, 0x1e, 0x00, 0x39, 0x0f, 0x1b, 0x1d, 0xe5, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x67, 0x69, 0x73, 0x74, 0x06, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0xc0, 0x1e, 0xfc, 0x8e ];
    let pkt = DecodePacket(dns_pkt);

    //println!("DEBUG : {:?}", pkt);
    
    match pkt {
    	UdpPacket(eth_hdr, ip_hdr,  udp_hdr,  payload) => {
			println!("{:?}", eth_hdr);
            println!("{:?}", ip_hdr);
            println!("{:?}", udp_hdr);
            println!("{:?}", payload);

            assert_eq!(eth_hdr.Source, );
            assert_eq!(eth_hdr.Destination, );
            assert_eq!(eth_hdr.Type, 0x0800);

            assert_eq!(ip_hdr.Version, 4);
            assert_eq!(ip_hdr.Ihl, );
            assert_eq!(ip_hdr.DiffServField, );
            assert_eq!(ip_hdr.TotalLength, );
            assert_eq!(ip_hdr.HeaderLength, );
            assert_eq!(ip_hdr.Id, );
            assert_eq!(ip_hdr.Flags, );
            assert_eq!(ip_hdr.frag_offset, );
            assert_eq!(ip_hdr.Ttl, );
            assert_eq!(ip_hdr.Protocol, );
            assert_eq!(ip_hdr.Checksum, );
            assert_eq!(ip_hdr.Source, );
            assert_eq!(ip_hdr.Destination, );

            assert_eq!(udp_hdr.SourcePort, 52);
            assert_eq!(udp_hdr.DestinationPort, 56862);
            assert_eq!(udp_hdr.Length, 57);
            
            //assert_eq!(); // can you assert_eq on a slice's contents?
    	}, 
    	_ => { fail!("wrong packet type to start out with"); }
    }
    

    /*
    Ethernet
    - src: e0:91:f5:e3:07:be
    - dst: 9c:2a:70:66:92:e3
    - type: 0x0800

    IP
	- version: 4
	- header length: 20 bytes
	- diff services field: 0x00
	- total len: 77 (119) ?
	- id : 0x4eeb
	- flags: 0x02 (don't fragment)
	- frag_offset = 0
	- ttl: 248
	- protocol: 17 (udp)
	- header checksum: 0x2c71
	- source: 65.32.5.111
	- dest: 192.168.0.12

    UDP
	- src port: 53
	- dst port: 56862
	- len: 57
	*/
} 