#[feature(globs)];

extern mod extra;

use std::str;
use std::comm::*;
use std::hashmap::*;
use std::task::*;
use std::os;
use std::io::*;
use std::io::buffered::*;
use std::io::timer;
use std::io::net::tcp::*;
use std::io::net::ip::{SocketAddr,IpAddr,Ipv4Addr};

use extra::json;
use extra::getopts::*;
use extra::serialize::{Encodable, Decodable, Decoder};


use rustpcap::*;
mod rustpcap;

fn internal_packet_router(port: Port<~[u8]>) {
    //let mut timer = std::io::timer::Timer::new().expect("couldn't create a timer");
    let mut map: HashMap<~[u8], ~str> = HashMap::new();
    map.insert(~[0x00, 0x01, 0x02, 0x03, 0x04, 0x05], ~"test");
    map.insert(~[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f], ~"test2");

    let mut stdout_writer = std::io::stdio::stdout();
    
    let mut encoder = json::Encoder::new(&mut stdout_writer as &mut std::io::Writer);
    //let mut encoder = json::Encoder::new(&mut stdout_writer);
    map.encode(&mut encoder);

    // fail!()
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
    let args = os::args();
    let opts = ~[
        optflag("host"),
        optopt("join"),
        reqopt("dev")
    ];
    
    let args = match getopts(args.tail(), opts) {
        Ok(m) => { m }
        Err(f) => { fail!(f.to_err_msg()); }
    };

    if !args.opt_present("host") && !args.opt_present("join") {
        fail!("Must host or join.")
    }

    if args.opt_present("host") && args.opt_present("join") {
        fail!("Can't host and join.")
    }

    /*
 
    let dev = args.opt_str("dev").expect("device is required");
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

    */
    
    if args.opt_present("host") {
        // host
        let saddr = SocketAddr {ip: Ipv4Addr(0,0,0,0), port: 8602 };
        let mut acceptor = match TcpListener::bind(saddr).listen() {
            None => {
                error!("bind or listen failed :^D");
                return;
            }
            Some(acceptor) => acceptor,
        };
        loop {
            // <lolwut>
            // OK, we're sort of shadowing an IoError here. Perhaps this should be done in a
            // separate task so that it can safely fail...
            let mut error = None;
            let optstream = io_error::cond.trap(|e| {
                error = Some(e);
            }).inside(|| {
                acceptor.accept()
            });
            // </lolwut>

            do spawn {
                println("unwrapping stream");
                let mut stream = BufferedStream::new(optstream.unwrap());
                let mut json = match json::from_reader(&mut stream as &mut std::io::Reader) { // not sure if this is right
                    Ok(j) => { println!("okay"); j } // never gets here.
                    Err(e) => { fail!("asdfasdf") } // (well, or here for that matter)
                };
                let mut decoder = json::Decoder::new(json);
                loop {
                    let map: HashMap<~[u8], ~str> = Decodable::decode(&mut decoder);
                    println!("decoded {:?}", map);
                }
            }
        }

    } else if args.opt_present("join") {
        let remote_host = args.opt_str("join").expect("join requires an argument");
        let saddr: SocketAddr = from_str(remote_host).expect("failed to parse the remote host");
        let mut conn = TcpStream::connect(saddr).expect("failed to connect");
        let mut encoder = json::Encoder::new(&mut conn as &mut std::io::Writer);
        loop {
            let mut map: HashMap<~[u8], ~str> = HashMap::new();
            map.encode(&mut encoder);
            println("sent, sleeping");
            timer::sleep(2000);
        }
        println!("{:?}", remote_host);
    }
}
