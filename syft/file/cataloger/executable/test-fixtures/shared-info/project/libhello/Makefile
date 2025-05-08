.PHONY: all linux windows mac

BIN=../../bin

all:  $(BIN)/libhello.so  $(BIN)/libhello.dll $(BIN)/libhello.dylib

linux: $(BIN)/libhello.so

windows: $(BIN)/libhello.dll

mac: $(BIN)/libhello.dylib

$(BIN)/libhello.so:
	gcc -shared -fPIC -o $(BIN)/libhello.so hello.c

$(BIN)/libhello.dll:
	x86_64-w64-mingw32-gcc -shared -o $(BIN)/hello.dll hello.c -Wl,--out-implib,$(BIN)/libhello.a

$(BIN)/libhello.dylib:
	o64-clang -dynamiclib -o $(BIN)/libhello.dylib hello.c

clean:
	rm -f $(BIN)/libhello.so $(BIN)/hello.dll $(BIN)/libhello.dylib $(BIN)/libhello.a
