IMAGE = "centos:8"
IMAGE_CLEAN = $(shell echo $(IMAGE) | tr ":" "_")
IMGBOM_DIR = imgbom-reports
IMGBOM_REPORT = $(IMGBOM_DIR)/$(IMAGE_CLEAN).json
INLINE_DIR = inline-reports
INLINE_REPORT = $(INLINE_DIR)/$(IMAGE_CLEAN)-content-os.json

.PHONY: bootstrap

all: compare

compare: $(INLINE_REPORT) $(IMGBOM_REPORT)
	docker build -t compare-imgbom:latest .
	docker run compare-imgbom:latest $(IMAGE)

$(INLINE_REPORT):
	echo "Creating $(INLINE_REPORT)..."
	mkdir -p $(INLINE_DIR)
	curl -s https://ci-tools.anchore.io/inline_scan-v0.7.0 | bash -s -- -p -r $(IMAGE)
	mv anchore-reports/* $(INLINE_DIR)/
	rmdir anchore-reports

$(IMGBOM_REPORT):
	echo "Creating $(IMGBOM_REPORT)..."
	mkdir -p $(IMGBOM_DIR)
	docker pull $(IMAGE)
	go run ../main.go centos:latest -o json > $(IMGBOM_REPORT)
