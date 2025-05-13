.PHONY: all linux windows mac

BIN=../../bin

all: $(BIN)/hello_linux $(BIN)/hello.exe $(BIN)/hello_mac

linux: $(BIN)/libhello.so

windows: $(BIN)/libhello.dll

mac: $(BIN)/libhello.dylib

$(BIN)/hello_linux:
	gcc hello.c -o $(BIN)/hello_linux

$(BIN)/hello.exe:
	x86_64-w64-mingw32-gcc hello.c -o $(BIN)/hello.exe

$(BIN)/hello_mac:
	o64-clang hello.c -o $(BIN)/hello_mac

clean:
	rm -f $(BIN)/hello_linux $(BIN)/hello.exe $(BIN)/hello_mac
