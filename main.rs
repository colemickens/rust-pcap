#[feature(globs)];

extern mod std;
extern mod extra;

use std::{cast,io,os,ptr,task};
use rustpcap::*;
use std::str;

mod rustpcap;

fn main() {
    let dev = "enp3s0";
    let filter = "";
 
    let cap_dev = PcapOpenDevice(dev);
    match cap_dev {
        Some(cap_dev) => {
            let res = cap_dev.SetFilter(dev, filter);
            match res {
                Err(err) => { fail!(err); }
                Ok(()) => {}
            }
            loop {
                let pkt = cap_dev.NextPacketEx();
                match pkt {
                    Ok(pkt) => {
                        println(format!("{:?}", pkt.payload));

                        let sy1 = pkt.payload.map(|&e| if e >= 0 && e < 128 { e } else { 0 });
                        let sy2 = sy1.into_ascii();
                        let sy3 = sy2.as_str_ascii();
                        println(sy3);
                    },
                    Err(Timeout) => {

                    }
                    Err(err) => {
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
