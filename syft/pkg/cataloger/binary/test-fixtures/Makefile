BIN=classifiers/bin
FINGERPRINT_FILE=$(BIN).fingerprint


.DEFAULT_GOAL := fixtures

# requirement 1: 'fixtures' goal to generate any and all test fixtures
fixtures: download

# requirement 2: 'fingerprint' goal to determine if the fixture input that indicates any existing cache should be busted
fingerprint: clean-fingerprint $(FINGERPRINT_FILE)

list: ## list all managed binaries and snippets
	go run ./manager list

download: ## download only binaries that are not covered by a snippet
	go run ./manager download $(name) --skip-if-covered-by-snippet

download-all: ## download all managed binaries
	go run ./manager download

add-snippet: ## add a new snippet from an existing binary
	go run ./manager add-snippet

# requirement 3: we always need to recalculate the fingerprint based on source regardless of any existing fingerprint
.PHONY: $(FINGERPRINT_FILE)
$(FINGERPRINT_FILE): ## prints the sha256sum of the any input to the download command (to determine if there is a cache miss)
	@sha256sum ./config.yaml > $(FINGERPRINT_FILE)

# requirement 4: 'clean' goal to remove all generated test fixtures
clean:  ## clean up all downloaded binaries
	rm -rf $(BIN)

clean-fingerprint: ## clean up all legacy fingerprint files
	@find $(BIN) -name '*.fingerprint' -delete


## Halp! #################################

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

.PHONY: default list download download-all clean clean-fingerprint add-snippet fingerprint