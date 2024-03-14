BIN=./bin
TOOL_IMAGE=localhost/syft-shared-info-build-tools:latest
VERIFY_FILE=actual_verify

all: build
tools-check:
	@sha256sum -c Dockerfile.sha256 || (echo "Tools Dockerfile has changed" && exit 1)

tools:
	@(docker inspect $(TOOL_IMAGE) > /dev/null && make tools-check) || (docker build -t $(TOOL_IMAGE) . && sha256sum Dockerfile > Dockerfile.sha256)

build: tools
	mkdir -p $(BIN)
	docker run --platform linux/amd64 -i -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) make

debug:
	docker run --platform linux/amd64 -i --rm -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) bash

cache.fingerprint:
	@find project Dockerfile Makefile -type f -exec md5sum {} + | awk '{print $1}' | sort | tee cache.fingerprint

clean:
	rm -f $(BIN)/*

.PHONY: build verify debug build-image build-bins clean dockerfile-check cache.fingerprint
