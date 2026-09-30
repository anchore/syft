BIN=../bin

all: $(BIN)/hello_gdc

$(BIN)/hello_gdc: hello.d
	gdc hello.d -o $(BIN)/hello_gdc

clean:
	rm -f $(BIN)/hello_gdc
