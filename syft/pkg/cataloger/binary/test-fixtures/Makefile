.PHONY: default list download download-all cache.fingerprint

.DEFAULT_GOAL := default

default: download

list: ## list all managed binaries and snippets
	go run ./manager list

download: ## download only binaries that are not covered by a snippet
	go run ./manager download $(name) --skip-if-covered-by-snippet

download-all: ## download all managed binaries
	go run ./manager download

add-snippet: ## add a new snippet from an existing binary
	go run ./manager add-snippet

cache.fingerprint: ## prints the sha256sum of the any input to the download command (to determine if there is a cache miss)
	@cat ./config.yaml | sha256sum | awk '{print $$1}' | tee cache.fingerprint

clean: ## clean up all downloaded binaries
	rm -rf ./classifiers/bin

## Halp! #################################

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'