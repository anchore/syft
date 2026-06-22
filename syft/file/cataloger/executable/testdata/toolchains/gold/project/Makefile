BIN=../bin

all: $(BIN)/hello_gold

$(BIN)/hello_gold: hello.c
	gcc hello.c -fuse-ld=gold -o $(BIN)/hello_gold

clean:
	rm -f $(BIN)/hello_gold
