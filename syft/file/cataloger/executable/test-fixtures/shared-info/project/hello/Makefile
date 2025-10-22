.PHONY: all linux windows mac

BIN=../../bin

all: $(BIN)/hello_linux $(BIN)/hello.exe $(BIN)/hello_mac $(BIN)/hello_mac_universal

linux: $(BIN)/libhello.so

windows: $(BIN)/libhello.dll

mac: $(BIN)/libhello.dylib $(BIN)/hello_mac_universal

$(BIN)/hello_linux:
	gcc hello.c -o $(BIN)/hello_linux

$(BIN)/hello.exe:
	x86_64-w64-mingw32-gcc hello.c -o $(BIN)/hello.exe

$(BIN)/hello_mac:
	o64-clang hello.c -o $(BIN)/hello_mac

$(BIN)/hello_mac_universal:
	o64-clang -arch arm64 -arch x86_64 hello.c -o $(BIN)/hello_mac_universal

clean:
	rm -f $(BIN)/hello_linux $(BIN)/hello.exe $(BIN)/hello_mac $(BIN)/hello_mac_universal
