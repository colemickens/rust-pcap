all:
	rm ./bin/*.so
	rustc --lib decode.rs
	rustc --lib pcapfe.rs
	mv *.so ./bin/

test:
	rustc --test test.rs -L ./bin/
	./test
	rm ./test