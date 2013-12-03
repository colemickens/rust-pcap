#[feature(globs)];

use rustpcap::*;
mod rustpcap;

fn main() {
    let dev = "enp3s0";
    let filter = "tcp dst port 80";
 
    let cap_dev = PcapOpenDevice(dev);
    match cap_dev {
        Some(cap_dev) => {
            let res = cap_dev.SetFilter(dev, filter);
            match res {
                Err(err) => { fail!(err); }
                Ok(()) => {}
            }
            loop {
                println("=======================================================");
                let pkt = cap_dev.NextPacketEx();
                match pkt {
                    Ok(pkt) => {
                        println(format!("{:?}", pkt.payload));

                        let strings = pkt.payload.map(|&e| if e < 128 { e } else { 0 });
                        let strings = strings.into_ascii();
                        let strings = strings.as_str_ascii();
                        println("-----");
                        println(strings);
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
