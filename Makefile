all:
	rustc --lib decode.rs
	rustc --lib pcapfe.rs
	rustc --test test.rs -L .
	rm -rf ./bin/
	mkdir bin
	mv *.so test ./bin/
	./bin/test