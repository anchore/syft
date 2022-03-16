DESTINATION=binaries

all: $(DESTINATION)/hello-mach-o-arm64  $(DESTINATION)/hello-linux-arm  $(DESTINATION)/hello-linux-ppc64le  $(DESTINATION)/hello-win-amd64

$(DESTINATION)/hello-mach-o-arm64:
	mkdir -p $(DESTINATION)
	GOARCH=arm64 GOOS=darwin ./src/build.sh $(DESTINATION)/hello-mach-o-arm64

$(DESTINATION)/hello-linux-arm:
	mkdir -p $(DESTINATION)
	GOARCH=arm GOOS=linux ./src/build.sh $(DESTINATION)/hello-linux-arm

$(DESTINATION)/hello-linux-ppc64le:
	mkdir -p $(DESTINATION)
	GOARCH=ppc64le GOOS=linux ./src/build.sh $(DESTINATION)/hello-linux-ppc64le

$(DESTINATION)/hello-win-amd64:
	mkdir -p $(DESTINATION)
	GOARCH=amd64 GOOS=windows ./src/build.sh $(DESTINATION)/hello-win-amd64

# we need a way to determine if CI should bust the test cache based on the source material
$(DESTINATION).fingerprint: clean
	mkdir -p $(DESTINATION)
	find src -type f -exec sha256sum {} \; | sort | tee /dev/stderr | tee $(DESTINATION).fingerprint
	sha256sum $(DESTINATION).fingerprint

.PHONY: clean
clean:
	rm -f $(DESTINATION)/*
