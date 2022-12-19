all: build validate

.PHONY: build
build:
	docker build -t spdx-java-tools:latest .

validate:
	docker run --rm -v $(shell pwd)/${FILE}:/test.spdx spdx-java-tools:latest Verify /test.spdx
