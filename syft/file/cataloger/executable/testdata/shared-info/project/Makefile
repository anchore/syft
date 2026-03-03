# invoke all make files in subdirectories
.PHONY: all hello libhello

all: hello libhello ../bin/gcc-amd64-darwin-exec-debug

hello:
	$(MAKE) -C hello

libhello:
	$(MAKE) -C libhello

../bin/gcc-amd64-darwin-exec-debug:
	curl -L -o ../bin/gcc-amd64-darwin-exec-debug  https://github.com/golang/tools/raw/9ed98faabadd2cb94de86d5290b1c6942b7c4877/cmd/splitdwarf/internal/macho/testdata/gcc-amd64-darwin-exec-debug
