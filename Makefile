all:
	# generate the bindings (broken for some reason)
	# ../../crabtw/rust-bindgen/bindgen -builtins -l pcap -match pcap.h -o pcap.rs /usr/include/pcap/pcap.h -I/usr/lib/clang/3.3/include/
	
	# build the library
	rustc --lib pcapfe.rs > logs/build_log_pcapfe.txt 2>&1

	# run the packet decode tests
	rustc pcapfe.rs --test > logs/test_log_pcapfe.txt 2>&1

	# build the TUFE example
	rustc -L . examples/tufe/main.rs -o tufe > logs/build_log_tufe.txt 2>&1
	
	# build the DUMP example
	rustc -L . examples/dump/main.rs -o dump > logs/build_log_dump.txt 2>&1

clean:
	rm dump
	rm tufe
	rm libpcapfe*.so