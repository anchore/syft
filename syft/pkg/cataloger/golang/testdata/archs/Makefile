DESTINATION=binaries
FINGERPRINT_FILE=$(DESTINATION).fingerprint

ifndef DESTINATION
    $(error DESTINATION is not set)
endif

.DEFAULT_GOAL := fixtures

# requirement 1: 'fixtures' goal to generate any and all test fixtures
fixtures: $(DESTINATION)

# requirement 2: 'fingerprint' goal to determine if the fixture input that indicates any existing cache should be busted
fingerprint: $(DESTINATION).fingerprint

$(DESTINATION): $(DESTINATION)/hello-mach-o-arm64 $(DESTINATION)/hello-linux-arm $(DESTINATION)/hello-linux-ppc64le $(DESTINATION)/hello-win-amd64

$(DESTINATION)/hello-mach-o-arm64:
	GOARCH=arm64 GOOS=darwin ./src/build.sh $(DESTINATION)/hello-mach-o-arm64

$(DESTINATION)/hello-linux-arm:
	GOARCH=arm GOOS=linux ./src/build.sh $(DESTINATION)/hello-linux-arm

$(DESTINATION)/hello-linux-ppc64le:
	GOARCH=ppc64le GOOS=linux ./src/build.sh $(DESTINATION)/hello-linux-ppc64le

$(DESTINATION)/hello-win-amd64:
	GOARCH=amd64 GOOS=windows ./src/build.sh $(DESTINATION)/hello-win-amd64

# requirement 3: we always need to recalculate the fingerprint based on source regardless of any existing fingerprint
.PHONY: $(FINGERPRINT_FILE)
$(FINGERPRINT_FILE):
	@find src -type f -exec sha256sum {} \; | sort -k2 > $(FINGERPRINT_FILE)
	@#cat $(FINGERPRINT_FILE) | sha256sum | awk '{print $$1}'

# requirement 4: 'clean' goal to remove all generated test fixtures
.PHONY: clean
clean:
	rm -rf $(DESTINATION)
