extern mod pcapfe;

use pcapfe::DecodePacket;

#[test]
fn test_decode_udp_packet() {
    let dns_pkt: &[u8] = [ 0x00 ];
    let pkt = DecodePacket(dns_pkt);

    //println!("DEBUG : {:?}", pkt);

    assert_eq!(10u, 10u);
    // HELP: why does this test fail?
    // commenting lines 7 and 8 out allow it to pass?
} 