all:
	# ../../crabtw/rust-bindgen/bindgen -builtins -l pcap -match pcap.h -o pcap.rs /usr/include/pcap/pcap.h -I/usr/lib/clang/3.3/include/
	# somehow that broke all of the sudden?
	# gotta revert the pcap.rs generated to a good one, check this later, I guess
	rustc --lib pcapfe.rs > build_log.txt 2>&1
