#[feature(globs)];

extern mod extra;
extern mod pcapfe;

use std::str;
use std::os;
use std::io::*;
use extra::getopts::*;

use pcapfe::*;

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

    let cap_dev = PcapOpenDevice(dev);
    match cap_dev {
        Some(cap_dev) => {
            /*
            let res = cap_dev.SetFilter(dev, "");
            match res {
                Err(err) => { fail!(err); }
                Ok(()) => {
                    println("set filter");
                }
            }
            */
            loop {
                println!("======");
                let pkt = cap_dev.NextPacketEx();
                match pkt {
                    Ok(pkt) => {
                        let temp_payload = str::from_utf8_owned(pkt.payload.map(|&e| if e > 31 && e < 127 { e } else { '.' as u8 }));
                        println!("{:?}", temp_payload);
                        println!("++");
                        pp(pkt.payload);
                        println!("--");
                        let dpkt = DecodePacket(pkt.payload);
                        match dpkt {
                            TcpPacket(ether_hdr, ip_hdr, tcp_hdr, payload) => {
                                let temp_payload = str::from_utf8_owned(payload.map(|&e| if e > 31 && e < 127 { e } else { '.' as u8 }));
                                println!("{:?}", temp_payload);
                            }
                            _ => {
                                println!("nontcp packet");
                            }
                        }
                    },
                    Err(Timeout) => {

                    }
                    Err(_) => {
                        println("failed to set capture next packet");
                    }
                }
            }   
        },
        None => {
            fail!("Failed to open device.");
            //fail!(fmt!("Failed to open dev {}", "enp3s0");
        }
    }
}