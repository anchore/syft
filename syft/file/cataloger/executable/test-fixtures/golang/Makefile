BIN=./bin
TOOL_IMAGE=localhost/syft-golang-build-tools:latest
FINGERPRINT_FILE=$(BIN).fingerprint

ifndef BIN
    $(error BIN is not set)
endif

.DEFAULT_GOAL := fixtures

# requirement 1: 'fixtures' goal to generate any and all test fixtures
fixtures: build

# requirement 2: 'fingerprint' goal to determine if the fixture input that indicates any existing cache should be busted
fingerprint: $(FINGERPRINT_FILE)

tools-check:
	@sha256sum -c Dockerfile.sha256 || (echo "Tools Dockerfile has changed" && exit 1)

tools:
	@(docker inspect $(TOOL_IMAGE) > /dev/null && make tools-check) || \
		(docker build -t $(TOOL_IMAGE) . && sha256sum Dockerfile > Dockerfile.sha256)

build: tools
	@mkdir -p $(BIN)
	docker run -i -v $(shell pwd)/$(BIN):/out $(TOOL_IMAGE) sh -c \
		"cp /hello_linux /hello_mac /hello.exe /out/"

debug:
	docker run -it --rm -v $(shell pwd):/mount -w /mount $(TOOL_IMAGE) sh

# requirement 3: we always need to recalculate the fingerprint based on source regardless of any existing fingerprint
.PHONY: $(FINGERPRINT_FILE)
$(FINGERPRINT_FILE):
	@find . -maxdepth 1 -type f \( -name "*.go" -o -name "go.*" -o -name "Dockerfile" -o -name "Makefile" \) \
		-exec sha256sum {} \; | sort -k2 > $(FINGERPRINT_FILE)

# requirement 4: 'clean' goal to remove all generated test fixtures
clean:
	rm -rf $(BIN) Dockerfile.sha256 $(FINGERPRINT_FILE)

.PHONY: tools tools-check build debug clean fixtures fingerprint
