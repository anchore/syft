BIN=./bin
TOOL_IMAGE=localhost/syft-bin-build-tools:latest
VERIFY_FILE=actual_verify

all: build verify

tools-check:
	@sha256sum -c Dockerfile.sha256 || (echo "Tools Dockerfile has changed" && exit 1)

# for selfrando...
# docker buildx build --platform linux/amd64 -t $(TOOL_IMAGE) .

tools:
	@(docker inspect $(TOOL_IMAGE) > /dev/null && make tools-check) || (docker build -t $(TOOL_IMAGE) . && sha256sum Dockerfile > Dockerfile.sha256)

build: tools
	mkdir -p $(BIN)
	docker run -i -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) make

verify: tools
	@rm -f $(VERIFY_FILE)
	docker run -i -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) make verify > $(VERIFY_FILE)
	@python ./differ expected_verify $(VERIFY_FILE)

debug:
	docker run -i --rm -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) bash

cache.fingerprint:
	@find project Dockerfile Makefile -type f -exec md5sum {} + | awk '{print $1}' | sort | tee cache.fingerprint

clean:
	rm -f $(BIN)/*

.PHONY: build verify debug build-image build-bins clean dockerfile-check cache.fingerprint
