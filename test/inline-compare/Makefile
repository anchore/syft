ifndef SYFT_CMD
	SYFT_CMD = go run ../../main.go
endif

IMAGE_CLEAN = $(shell echo $(COMPARE_IMAGE) | tr ":" "_")
SYFT_DIR = syft-reports
SYFT_REPORT = $(SYFT_DIR)/$(IMAGE_CLEAN).json
INLINE_DIR = inline-reports
INLINE_REPORT = $(INLINE_DIR)/$(IMAGE_CLEAN)-content-os.json

ifndef SYFT_DIR
	$(error SYFT_DIR is not set)
endif

ifndef INLINE_DIR
	$(error INLINE_DIR is not set)
endif

.PHONY: all
.DEFAULT_GOAL :=
all: clean-syft
	./compare-all.sh

.PHONY: compare-image
compare-image: $(SYFT_REPORT) $(INLINE_REPORT)
	./compare.py $(COMPARE_IMAGE)

.PHONY: gather-image
gather-image: $(SYFT_REPORT) $(INLINE_REPORT)

$(INLINE_REPORT):
	echo "Creating $(INLINE_REPORT)..."
	mkdir -p $(INLINE_DIR)
	curl -s https://ci-tools.anchore.io/inline_scan-v0.7.0 | bash -s -- -p -r $(COMPARE_IMAGE)
	mv anchore-reports/* $(INLINE_DIR)/
	rmdir anchore-reports

$(SYFT_REPORT):
	echo "Creating $(SYFT_REPORT)..."
	mkdir -p $(SYFT_DIR)
	$(SYFT_CMD) $(COMPARE_IMAGE) -o json > $(SYFT_REPORT)

.PHONY: clean
clean: clean-syft
	rm -f $(INLINE_DIR)/*

.PHONY: clean-syft
clean-syft:
	rm -f $(SYFT_DIR)/*