IMAGE = "centos:8"
IMAGE_CLEAN = $(shell echo $(IMAGE) | tr ":" "_")
syft_DIR = syft-reports
syft_REPORT = $(syft_DIR)/$(IMAGE_CLEAN).json
INLINE_DIR = inline-reports
INLINE_REPORT = $(INLINE_DIR)/$(IMAGE_CLEAN)-content-os.json

ifndef syft_DIR
	$(error syft_DIR is not set)
endif

ifndef INLINE_DIR
	$(error INLINE_DIR is not set)
endif

.PHONY: all
all: compare

.PHONY: compare
compare: $(INLINE_REPORT) $(syft_REPORT)
	docker build -t compare-syft:latest .
	docker run compare-syft:latest $(IMAGE)

$(INLINE_REPORT):
	echo "Creating $(INLINE_REPORT)..."
	mkdir -p $(INLINE_DIR)
	curl -s https://ci-tools.anchore.io/inline_scan-v0.7.0 | bash -s -- -p -r $(IMAGE)
	mv anchore-reports/* $(INLINE_DIR)/
	rmdir anchore-reports

$(syft_REPORT):
	echo "Creating $(syft_REPORT)..."
	mkdir -p $(syft_DIR)
	docker pull $(IMAGE)
	go run ../../main.go $(IMAGE) -o json > $(syft_REPORT)

.PHONY: clean
clean:
	rm -f $(INLINE_DIR)/*  $(syft_DIR)/*