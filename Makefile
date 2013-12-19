all:
	# ../../crabtw/rust-bindgen/bindgen -builtins -l pcap -match pcap.h -o pcap.rs /usr/include/pcap/pcap.h -I/usr/lib/clang/3.3/include/
	# somehow that broke all of the sudden?
	# gotta revert the pcap.rs generated to a good one, check this later, I guess
	rustc --lib pcapfe.rs > build_log_pcapfe.txt 2>&1
	rustc -L . examples/tufe/main.rs -o tufe > build_log_tufe.txt 2>&1
	rustc -L . examples/dump/main.rs -o dump > build_log_dump.txt 2>&1