all:
	rustc --lib pcapfe.rs
	rustc --lib pktutil.rs
	rustc --test pktutil_test.rs -L .
	mv *.so pktutil_test ./bin/
	rustc examples/dump.rs -L ./bin/
	rustc examples/tufe.rs -L ./bin/
	mv examples/{dump,tufe} ./bin/
	./bin/pktutil_test