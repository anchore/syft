BIN=./bin
TOOL_IMAGE=localhost/syft-bin-build-tools:latest
DIFF_IMAGE=localhost/differ:latest
VERIFY_FILE=actual_verify

all: build verify

tools-check:
	@sha256sum -c Dockerfile.sha256 || (echo "Tools Dockerfile has changed" && exit 1)

differ-check:
	@sha256sum -c ./differ/Dockerfile.sha256 || (echo "Differ Dockerfile has changed" && exit 1)

# for selfrando...
# docker buildx build --platform linux/amd64 -t $(TOOL_IMAGE) .

tools:
	@(docker inspect $(TOOL_IMAGE) > /dev/null && make tools-check) || (docker build -t $(TOOL_IMAGE) . && sha256sum Dockerfile > Dockerfile.sha256)
	@(docker inspect $(DIFF_IMAGE) > /dev/null && make differ-check) || (docker build -t $(DIFF_IMAGE) ./differ && sha256sum Dockerfile > ./differ/Dockerfile.sha256)

build: tools
	mkdir -p $(BIN)
	docker run -i -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) make

verify: tools
	@rm -f $(VERIFY_FILE)
	docker run -i -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) make verify > $(VERIFY_FILE)
	@docker run -i --rm -v $(shell pwd):/mount $(DIFF_IMAGE) /mount/expected_verify /mount/$(VERIFY_FILE) && (echo "PASS: Binary features built as with expected features" || (echo "FAIL: different binary features detected" && exit 1))

debug:
	docker run -i --rm -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) bash

cache.fingerprint:
	@find project Dockerfile Makefile -type f -exec md5sum {} + | awk '{print $1}' | sort | tee cache.fingerprint

clean:
	rm -f $(BIN)/*

.PHONY: build verify debug build-image build-bins clean dockerfile-check cache.fingerprint
