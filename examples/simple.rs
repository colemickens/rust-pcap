#[crate_id="pcap_example"];
#[crate_type="bin"];
#[license = "MIT"];

#[feature(globs)];

extern crate collections;
extern crate getopts;
extern crate native;
extern crate pcap;

use std::os;

use getopts::*;

use pcap::*;

#[start]
fn start(argc: int, argv: **u8) -> int {
    native::start(argc, argv,  main)
}

fn main() -> () {
    let args = os::args();
    let opts = ~[
        reqopt("d", "dev", "device", "enp3s0"),
    ];
    
    let args = match getopts(args.tail(), opts) {
        Ok(m) => { m }
        Err(f) => { fail!(f.to_err_msg()); }
    };


    let dev = args.opt_str("dev").expect("device is required");
    let cap_dev = pcap_open_dev(dev).ok().expect("failed to open capture device");

    loop {
        match cap_dev.next_packet_ex() {
            Ok(pcap_pkt) => {
                println!("{}", pcap_pkt.len);
                println!("{}", pcap_pkt.payload);
            },
            Err(NextEx_Timeout) => { },
            Err(t) => {
                fail!(format!("{:?}", t));
            }
        }
    }
}
