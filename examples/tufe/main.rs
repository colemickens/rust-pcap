#[feature(globs)];

extern mod extra;
extern mod pcapfe;

use std::str;
use std::comm::*;
use std::task::*;
use std::os;
use std::io::*;
use extra::getopts::*;

use pcapfe::*;

fn internal_packet_router(port: Port<~[u8]>) {
    /*
    let mut map: HashMap<~[u8], ~str> = HashMap::new();
    map.insert(~[0x00, 0x01, 0x02, 0x03, 0x04, 0x05], ~"test");
    map.insert(~[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f], ~"test2");

    let mut stdout_writer = std::io::stdio::stdout();
    
    let mut encoder = json::Encoder::new(&mut stdout_writer as &mut std::io::Writer);
    //let mut encoder = json::Encoder::new(&mut stdout_writer);
    map.encode(&mut encoder);
    */
    
    loop {
        let pkt = port.recv();
        println!("received!");
        let strings = str::from_utf8_owned(pkt.map(|&e| if e > 31 && e < 127 { e } else { '.' as u8 }));
        println!("{:?}", strings);
    }
}

fn packet_capture_loop(dev: &str, filter: &str, chan: Chan<~[u8]>) {
    let cap_dev = PcapOpenDevice(dev);
    match cap_dev {
        Some(cap_dev) => {
            let res = cap_dev.SetFilter(dev, filter);
            match res {
                Err(err) => { fail!(err); }
                Ok(()) => {
                    println("set filter");
                }
            }
            loop {
                let pkt = cap_dev.NextPacketEx();
                match pkt {
                    Ok(pkt) => {
                        println!("got a packet");
                        println!("{:?}", pkt.payload);
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

    let dev = args.opt_str("dev").expect("device is required");
    //let filter = "tcp dst port 80";
    let filter = ""; // TODO: revert
 
    let (pport, pchan): (Port<~[u8]>, Chan<~[u8]>) = Chan::new();
    
    spawn(proc(){
        internal_packet_router(pport);
    });
    //spawn(proc(){
        packet_capture_loop(dev, filter, pchan);
    //});

    /*
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
                let mut stream = BufferedStream::new(optstream.unwrap());
                println("about to match");
                let mut json = match json::from_reader(&mut stream as &mut std::io::Reader) { // not sure if this is right
                    Ok(j) => { println!("okay"); j } // never gets here.
                    Err(e) => { println!("failing"); fail!("asdfasdf") } // (well, or here for that matter)
                };
                let mut decoder = json::Decoder::new(json);
                loop {
                    let map: HashMap<~str, ~str> = Decodable::decode(&mut decoder);
                    println!("decoded {:?}", map);
                }
            }
        }

    } else if args.opt_present("join") {
        let remote_host = args.opt_str("join").expect("join requires an argument");
        let saddr: SocketAddr = from_str(remote_host).expect("failed to parse the remote host");
        let mut conn = TcpStream::connect(saddr).expect("failed to connect");
        //let mut stream = BufferedStream::new(conn);
        //let mut encoder = json::Encoder::new(&mut stream as &mut std::io::Writer);
        let mut encoder = json::Encoder::new(&mut conn as &mut std::io::Writer);
        loop {
            let mut map: HashMap<~str, ~str> = HashMap::new();
            map.insert(~"test", ~"test2");
            map.insert(~"test3", ~"test4");
            map.encode(&mut encoder);
            println("sent, sleeping");
            timer::sleep(2000);
        }
        println!("{:?}", remote_host);
    }
    */
}
