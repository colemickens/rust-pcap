#[feature(globs)];

extern mod extra;
extern mod pcapfe;
extern mod pktutil;

use std::os;

use extra::getopts::*;

use pcapfe::*;
use pktutil::*;

fn main() {
    let args = os::args();
    let opts = ~[
        reqopt("dev")
    ];
    
    let args = match getopts(args.tail(), opts) {
        Ok(m) => { m }
        Err(f) => { fail!(f.to_err_msg()); }
    };

    let dev = args.opt_str("dev").expect("device is required");

    match pcap_open_dev(dev) {
        Ok(cap_dev) => {
            loop {
                println!("======");
                let pkt = cap_dev.next_packet_ex();
                match pkt {
                    Ok(pkt) => {
                        let dpkt = decode_packet(pkt.payload);
                        match dpkt {
                            UdpPacket(ether_hdr, ip_hdr, udp_hdr, payload) => {
                                println!("---");
                                println!("{:?}", ether_hdr);
                                println!("{:?}", ip_hdr);
                                println!("{:?}", udp_hdr);
                                println!("{:?}", payload);
                                println!("---");
                            }
                            TcpPacket(ether_hdr, ip_hdr, tcp_hdr, payload) => {
                                println!("---");
                                println!("{:?}", ether_hdr);
                                println!("{:?}", ip_hdr);
                                println!("{:?}", tcp_hdr);
                                println!("{:?}", payload);
                                println!("---");
                            }
                            _ => {
                                println!("nontcp packet");
                            }
                        }
                    },
                    Err(t) => {
                        fail!(t);
                    }
                }
            }
        }
        Err(_) => {
            fail!("Failed to open device.");
        }
    }
}