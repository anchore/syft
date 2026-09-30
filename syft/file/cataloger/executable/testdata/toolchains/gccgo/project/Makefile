BIN=../bin

all: $(BIN)/hello_gccgo

$(BIN)/hello_gccgo: hello.go
	gccgo hello.go -o $(BIN)/hello_gccgo

clean:
	rm -f $(BIN)/hello_gccgo
