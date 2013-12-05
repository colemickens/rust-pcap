#[feature(globs)];

use std::str;
use std::comm;

use rustpcap::*;
mod rustpcap;

fn internal_packet_router(chan: comm::SharedChan<~str>) {
    let mut timer = std::io::timer::Timer::new().expect("couldn't create a timer");
    loop {
        chan.send(~"test");
        timer.sleep(3000);
    }
}

fn packet_capture_loop(dev: &str, filter: &str, chan: comm::SharedChan<~str>) {
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
                        //println(format!("{:?}", pkt.payload));

                        let strings = pkt.payload.map(|&e| if e > 31 && e < 127 { e } else { '.' as u8 });
                        let strings = str::from_utf8(strings);
                        chan.send(~"packet");
                        //chan.send(strings);
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
 
    let (port, chan) = stream();
    let chan = comm::SharedChan::new(chan);


    /*
    do spawn { internal_packet_router(chan.clone()); }
    do spawn { packet_capture_loop(dev, filter, chan.clone()); }

    This doesn't work, why do I have to do the clones separately?
    */
  
    let cchan1 = chan.clone();
    let cchan2 = chan.clone();

    do spawn { internal_packet_router(cchan1); }
    do spawn { packet_capture_loop(dev, filter, cchan2); }
    
    loop {
        let val = port.recv();
        println(format!("{}", val));
    }

}
