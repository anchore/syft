all: build validate

.PHONY: build
build:
	docker build -t spdx-java-tools:latest .

validate:
	docker run --rm -v ${FILE}:/home/build/${BASE} spdx-java-tools:latest Verify ${BASE}
