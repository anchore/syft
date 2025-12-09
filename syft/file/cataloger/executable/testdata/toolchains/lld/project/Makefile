BIN=../bin

all: $(BIN)/hello_lld

$(BIN)/hello_lld: hello.c
	clang hello.c -fuse-ld=lld -o $(BIN)/hello_lld

clean:
	rm -f $(BIN)/hello_lld
