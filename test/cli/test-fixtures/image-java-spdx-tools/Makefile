all: build validate

IMAGE := "spdx-java-tools:latest"

.PHONY: build
build:
	docker build -t spdx-java-tools:latest .

validate:
	docker run --rm -v $(DIR):/home/build/ $(IMAGE) Verify /home/build/$(BASE)
