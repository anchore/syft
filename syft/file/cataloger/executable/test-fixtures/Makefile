BIN=./bin
TOOL_IMAGE=localhost/syft-bin-build-tools:latest
VERIFY_FILE=actual_verify

all: build verify

dockerfile-check:
	@sha256sum -c Dockerfile.sha256 || (echo "Dockerfile has changed" && exit 1)

# for selfrando...
# docker buildx build --platform linux/amd64 -t $(TOOL_IMAGE) .

tools:
	@(docker inspect $(TOOL_IMAGE) > /dev/null && make dockerfile-check) || (docker build -t $(TOOL_IMAGE) . && sha256sum Dockerfile > Dockerfile.sha256)

build: tools
	mkdir -p $(BIN)
	docker run -it -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) make

verify: tools
	@rm $(VERIFY_FILE)
	docker run -it -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) make verify  | tee $(VERIFY_FILE)
	@diff -u expected_verify $(VERIFY_FILE) && (echo "PASS" || (echo "FAIL" && exit 1))

debug:
	docker run -it --rm -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) bash

cache.fingerprint:
	@find project Dockerfile Makefile -type f -exec md5sum {} + | awk '{print $1}' | sort | tee cache.fingerprint

clean:
	rm -f $(BIN)/*

.PHONY: build verify debug build-image build-bins clean dockerfile-check cache.fingerprint
