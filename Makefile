all:
	rustc lib.rs

gen:
	../crabtw/rust-bindgen/bindgen \
		-builtins \
		-l pcap \
		-o pcap.rs \
		/usr/include/pcap/pcap.h \
		-I/usr/lib/clang/3.3/include/

	echo '#[ignore(dead_code)]' | cat - pcap.rs > pcap.rs-temp && mv pcap.rs-temp pcap.rs

	cat << EOF > pcap.rs
			#[cfg(windows)]
			#[link(name="wpcap")]
			extern "C" {}

			#[cfg(not(windows))]
			#[link(name = "pcap")]
			extern "C" {}
	EOF