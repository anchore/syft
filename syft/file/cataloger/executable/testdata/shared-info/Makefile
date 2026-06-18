BIN=./bin
TOOL_IMAGE=localhost/syft-shared-info-build-tools:latest
VERIFY_FILE=actual_verify
FINGERPRINT_FILE=$(BIN).fingerprint

ifndef BIN
    $(error BIN is not set)
endif

.DEFAULT_GOAL := fixtures

# requirement 1: 'fixtures' goal to generate any and all test fixtures
fixtures: build

# requirement 2: 'fingerprint' goal to determine if the fixture input that indicates any existing cache should be busted
fingerprint: $(FINGERPRINT_FILE)

tools:
	@if docker image inspect $(TOOL_IMAGE) > /dev/null 2>&1 \
	   && test -f Dockerfile.sha256 \
	   && sha256sum --quiet -c Dockerfile.sha256 2>/dev/null; then \
	  : ; \
	else \
	  docker build --platform linux/amd64 -t $(TOOL_IMAGE) . \
	  && sha256sum Dockerfile > Dockerfile.sha256; \
	fi

build: tools
	@mkdir -p $(BIN)
	docker run --platform linux/amd64 -i -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) make

debug:
	docker run --platform linux/amd64 -i --rm -v $(shell pwd):/mount -w /mount/project $(TOOL_IMAGE) bash

# requirement 3: we always need to recalculate the fingerprint based on source regardless of any existing fingerprint
.PHONY: $(FINGERPRINT_FILE)
$(FINGERPRINT_FILE):
	@find project Dockerfile Makefile -type f -exec sha256sum {} \; | sort -k2 > $(FINGERPRINT_FILE)
	@#cat $(FINGERPRINT_FILE) | sha256sum | awk '{print $$1}'

# requirement 4: 'clean' goal to remove all generated test fixtures
clean:
	rm -rf $(BIN) Dockerfile.sha256 $(VERIFY_FILE) $(FINGERPRINT_FILE)

.PHONY: tools build debug clean
