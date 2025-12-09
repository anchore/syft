BIN=../bin

all: $(BIN)/hello_rust

$(BIN)/hello_rust: hello.rs
	rustc hello.rs -o $(BIN)/hello_rust

clean:
	rm -f $(BIN)/hello_rust
