BIN=../bin

all: $(BIN)/hello_gnat

$(BIN)/hello_gnat: hello.adb
	gnatmake hello.adb -o $(BIN)/hello_gnat

clean:
	rm -f $(BIN)/hello_gnat *.o *.ali
