#[feature(globs)];

use std::str;
use std::comm::*;
use std::task::*;

use rustpcap::*;
mod rustpcap;

fn internal_packet_router(port: Port<~[u8]>) {
    //let mut timer = std::io::timer::Timer::new().expect("couldn't create a timer");
    loop {
        let pkt = port.recv();
        let strings = str::from_utf8_owned(pkt.map(|&e| if e > 31 && e < 127 { e } else { '.' as u8 }));
        println!("{:?}", strings);
    }
}

fn packet_capture_loop(dev: &str, filter: &str, chan: SharedChan<~[u8]>) {
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
                        chan.send(pkt.payload);
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

fn main() {
    let dev = "enp3s0";
    let filter = "tcp dst port 80";
 
    let (pport, pchan): (Port<~[u8]>, Chan<~[u8]>) = stream();
    let pchan = SharedChan::new(pchan);
    let packet_chan1 = pchan.clone();
    let packet_chan2 = pchan.clone();

    spawn(proc(){
        internal_packet_router(pport);
    });
    spawn(proc(){
        packet_capture_loop(dev, filter, packet_chan2);
    });
}
