BIN=../bin

all: $(BIN)/hello_mold

$(BIN)/hello_mold: hello.c
	gcc hello.c -fuse-ld=mold -o $(BIN)/hello_mold

clean:
	rm -f $(BIN)/hello_mold
