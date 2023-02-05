BIN := syft
TEMP_DIR := ./.tmp

# Command templates #################################
LINT_CMD := $(TEMP_DIR)/golangci-lint run --tests=false
GOIMPORTS_CMD := $(TEMP_DIR)/gosimports -local github.com/anchore
RELEASE_CMD := $(TEMP_DIR)/goreleaser release --rm-dist
SNAPSHOT_CMD := $(RELEASE_CMD) --skip-publish --skip-sign --snapshot

# Tool versions #################################
GOLANGCILINT_VERSION := v1.51.0
GOSIMPORTS_VERSION := v0.3.5
BOUNCER_VERSION := v0.4.0
CHRONICLE_VERSION := v0.5.1
GORELEASER_VERSION := v1.15.1
YAJSV_VERSION := v1.4.1
COSIGN_VERSION := v1.13.1
QUILL_VERSION := v0.2.0

# Formatting variables #################################
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

# Test variables #################################
COMPARE_DIR := ./test/compare
COMPARE_TEST_IMAGE := centos:8.2.2004
COVERAGE_THRESHOLD := 62  # the quality gate lower threshold for unit test total % coverage (by function statements)

## Build variables #################################
VERSION := $(shell git describe --dirty --always --tags)
DIST_DIR := ./dist
SNAPSHOT_DIR := ./snapshot
CHANGELOG := CHANGELOG.md
OS := $(shell uname | tr '[:upper:]' '[:lower:]')
SNAPSHOT_BIN := $(realpath $(shell pwd)/$(SNAPSHOT_DIR)/$(OS)-build_$(OS)_amd64_v1/$(BIN))

ifndef VERSION
	$(error VERSION is not set)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

define safe_rm_rf
	bash -c 'test -z "$(1)" && false || rm -rf $(1)'
endef

define safe_rm_rf_children
	bash -c 'test -z "$(1)" && false || rm -rf $(1)/*'
endef

.DEFAULT_GOAL:=help


.PHONY: all
all: static-analysis test ## Run all linux-based checks (linting, license check, unit, integration, and linux compare tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: static-analysis
static-analysis: check-go-mod-tidy lint check-licenses check-json-schema-drift  ## Run all static analysis checks

.PHONY: test
test: unit integration validate-cyclonedx-schema benchmark cli ## Run all tests (currently unit, integration, linux compare, and cli tests)


## Bootstrapping targets #################################

.PHONY: bootstrap
bootstrap: $(TEMP_DIR) bootstrap-go bootstrap-tools ## Download and install all tooling dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMP_DIR)
	curl -sSfL https://raw.githubusercontent.com/anchore/quill/main/install.sh | sh -s -- -b $(TEMP_DIR)/ $(QUILL_VERSION)
	GO111MODULE=off GOBIN=$(realpath $(TEMP_DIR)) go get -u golang.org/x/perf/cmd/benchstat
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMP_DIR)/ $(GOLANGCILINT_VERSION)
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMP_DIR)/ $(BOUNCER_VERSION)
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMP_DIR)/ $(CHRONICLE_VERSION)
	.github/scripts/goreleaser-install.sh -d -b $(TEMP_DIR)/ $(GORELEASER_VERSION)
	# the only difference between goimports and gosimports is that gosimports removes extra whitespace between import blocks (see https://github.com/golang/go/issues/20818)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/rinchsan/gosimports/cmd/gosimports@$(GOSIMPORTS_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/neilpa/yajsv@$(YAJSV_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/sigstore/cosign/cmd/cosign@$(COSIGN_VERSION)

.PHONY: bootstrap-go
bootstrap-go:
	go mod download

$(TEMP_DIR):
	mkdir -p $(TEMP_DIR)


## Static analysis targets #################################

.PHONY: lint
lint:  ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINT_CMD)
	@[ -z "$(shell $(GOIMPORTS_CMD) -d .)" ] || (echo "goimports needs to be fixed" && false)

	# go tooling does not play well with certain filename characters, ensure the common cases don't result in future "go get" failures
	$(eval MALFORMED_FILENAMES := $(shell find . | grep -e ':'))
	@bash -c "[[ '$(MALFORMED_FILENAMES)' == '' ]] || (printf '\nfound unsupported filename characters:\n$(MALFORMED_FILENAMES)\n\n' && false)"

.PHONY: lint-fix
lint-fix:  ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(GOIMPORTS_CMD) -w .
	$(LINT_CMD) --fix
	go mod tidy

.PHONY: check-licenses
check-licenses:  ## Ensure transitive dependencies are compliant with the current license policy
	$(call title,Checking for license compliance)
	$(TEMP_DIR)/bouncer check ./...

check-go-mod-tidy:
	@ .github/scripts/go-mod-tidy-check.sh && echo "go.mod and go.sum are tidy!"

check-json-schema-drift:
	$(call title,Ensure there is no drift between the JSON schema and the code)
	@.github/scripts/json-schema-drift-check.sh

## Testing targets #################################

.PHONY: unit
unit: $(TEMP_DIR) fixtures  ## Run unit tests (with coverage)
	$(call title,Running unit tests)
	go test -coverprofile $(TEMP_DIR)/unit-coverage-details.txt $(shell go list ./... | grep -v anchore/syft/test)
	@.github/scripts/coverage.py $(COVERAGE_THRESHOLD) $(TEMP_DIR)/unit-coverage-details.txt

.PHONY: integration
integration:  ## Run integration tests
	$(call title,Running integration tests)
	go test -v ./test/integration

.PHONY: validate-cyclonedx-schema
validate-cyclonedx-schema:
	cd schema/cyclonedx && make

.PHONY: cli
cli: $(SNAPSHOT_DIR)  ## Run CLI tests
	chmod 755 "$(SNAPSHOT_BIN)"
	$(SNAPSHOT_BIN) version
	SYFT_BINARY_LOCATION='$(SNAPSHOT_BIN)' \
		go test -count=1 -timeout=15m -v ./test/cli


## Benchmark test targets #################################

.PHONY: benchmark
benchmark: $(TEMP_DIR)  ## Run benchmark tests and compare against the baseline (if available)
	$(call title,Running benchmark tests)
	go test -p 1 -run=^Benchmark -bench=. -count=7 -benchmem ./... | tee $(TEMP_DIR)/benchmark-$(VERSION).txt
	(test -s $(TEMP_DIR)/benchmark-main.txt && \
		$(TEMP_DIR)/benchstat $(TEMP_DIR)/benchmark-main.txt $(TEMP_DIR)/benchmark-$(VERSION).txt || \
		$(TEMP_DIR)/benchstat $(TEMP_DIR)/benchmark-$(VERSION).txt) \
			| tee $(TEMP_DIR)/benchstat.txt

.PHONY: show-benchstat
show-benchstat:
	@cat $(TEMP_DIR)/benchstat.txt


## Test-fixture-related targets #################################

# note: this is used by CI to determine if various test fixture cache should be restored or recreated
fingerprints:
	$(call title,Creating all test cache input fingerprints)

	# for IMAGE integration test fixtures
	cd test/integration/test-fixtures && \
		make cache.fingerprint

	# for JAVA BUILD test fixtures
	cd syft/pkg/cataloger/java/test-fixtures/java-builds && \
		make packages.fingerprint

	# for GO BINARY test fixtures
	cd syft/pkg/cataloger/golang/test-fixtures/archs && \
		make binaries.fingerprint

	# for RPM test fixtures
	cd syft/pkg/cataloger/rpm/test-fixtures && \
		make rpms.fingerprint

	# for INSTALL integration test fixtures
	cd test/install && \
		make cache.fingerprint

	# for CLI test fixtures
	cd test/cli/test-fixtures && \
		make cache.fingerprint

.PHONY: fixtures
fixtures:
	$(call title,Generating test fixtures)
	cd syft/pkg/cataloger/java/test-fixtures/java-builds && make
	cd syft/pkg/cataloger/rpm/test-fixtures && make

.PHONY: show-test-image-cache
show-test-image-cache:  ## Show all docker and image tar cache
	$(call title,Docker daemon cache)
	@docker images --format '{{.ID}} {{.Repository}}:{{.Tag}}' | grep stereoscope-fixture- | sort

	$(call title,Tar cache)
	@find . -type f -wholename "**/test-fixtures/cache/stereoscope-fixture-*.tar" | sort

.PHONY: show-test-snapshots
show-test-snapshots:  ## Show all test snapshots
	$(call title,Test snapshots)
	@find . -type f -wholename "**/test-fixtures/snapshot/*" | sort


## install.sh testing targets #################################

install-test: $(SNAPSHOT_DIR)
	cd test/install && \
		make

install-test-cache-save: $(SNAPSHOT_DIR)
	cd test/install && \
		make save

install-test-cache-load: $(SNAPSHOT_DIR)
	cd test/install && \
		make load

install-test-ci-mac: $(SNAPSHOT_DIR)
	cd test/install && \
		make ci-test-mac

# note: we cannot clean the snapshot directory since the pipeline builds the snapshot separately
.PHONY: compare-mac
compare-mac: $(TEMP_DIR) $(SNAPSHOT_DIR)  ## Run compare tests on build snapshot binaries and packages (Mac)
	$(call title,Running compare test: Run on Mac)
	$(COMPARE_DIR)/mac.sh \
			$(SNAPSHOT_DIR) \
			$(COMPARE_DIR) \
			$(COMPARE_TEST_IMAGE) \
			$(TEMP_DIR)

# note: we cannot clean the snapshot directory since the pipeline builds the snapshot separately
.PHONY: compare-linux
compare-linux: compare-test-deb-package-install compare-test-rpm-package-install  ## Run compare tests on build snapshot binaries and packages (Linux)

.PHONY: compare-test-deb-package-install
compare-test-deb-package-install: $(TEMP_DIR) $(SNAPSHOT_DIR)
	$(call title,Running compare test: DEB install)
	$(COMPARE_DIR)/deb.sh \
			$(SNAPSHOT_DIR) \
			$(COMPARE_DIR) \
			$(COMPARE_TEST_IMAGE) \
			$(TEMP_DIR)

.PHONY: compare-test-rpm-package-install
compare-test-rpm-package-install: $(TEMP_DIR) $(SNAPSHOT_DIR)
	$(call title,Running compare test: RPM install)
	$(COMPARE_DIR)/rpm.sh \
			$(SNAPSHOT_DIR) \
			$(COMPARE_DIR) \
			$(COMPARE_TEST_IMAGE) \
			$(TEMP_DIR)


## Code generation targets #################################

.PHONY: generate-json-schema
generate-json-schema:  ## Generate a new json schema
	cd schema/json && go run generate.go

.PHONY: generate-license-list
generate-license-list:  ## Generate an updated spdx license list
	go generate ./internal/spdxlicense/...
	gofmt -s -w ./internal/spdxlicense


## Build-related targets #################################

.PHONY: build
build: $(SNAPSHOT_DIR)  ## Build release snapshot binaries and packages

$(SNAPSHOT_DIR):  ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOT_DIR)" > $(TEMP_DIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMP_DIR)/goreleaser.yaml

	# build release snapshots
	$(SNAPSHOT_CMD) --config $(TEMP_DIR)/goreleaser.yaml

.PHONY: changelog
changelog: clean-changelog $(CHANGELOG)  ## Generate and show the changelog for the current unreleased version
	@docker run -it --rm \
		-v $(shell pwd)/$(CHANGELOG):/$(CHANGELOG) \
		rawkode/mdv \
			-t 748.5989 \
			/$(CHANGELOG)

$(CHANGELOG):
	$(TEMP_DIR)/chronicle -vv > $(CHANGELOG)

.PHONY: release
release: clean-dist $(CHANGELOG)
	$(call title,Publishing release artifacts)
	@.github/scripts/ci-check.sh

	# create a config with the dist dir overridden
	echo "dist: $(DIST_DIR)" > $(TEMP_DIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMP_DIR)/goreleaser.yaml

	bash -c "\
		$(RELEASE_CMD) \
			--config $(TEMP_DIR)/goreleaser.yaml \
			--release-notes <(cat $(CHANGELOG)) \
				 || (cat /tmp/quill-*.log && false)"

	# upload the version file that supports the application version update check (excluding pre-releases)
	.github/scripts/update-version-file.sh "$(DIST_DIR)" "$(VERSION)"

## Cleanup targets #################################

.PHONY: clean
clean: clean-dist clean-snapshot clean-test-image-cache  ## Remove previous builds, result reports, and test cache
	$(call safe_rm_rf_children,$(TEMP_DIR))

.PHONY: clean-snapshot
clean-snapshot:
	$(call safe_rm_rf,$(SNAPSHOT_DIR))
	rm -f $(TEMP_DIR)/goreleaser.yaml

.PHONY: clean-dist
clean-dist: clean-changelog
	$(call safe_rm_rf,$(DIST_DIR))
	rm -f $(TEMP_DIR)/goreleaser.yaml

.PHONY: clean-changelog
clean-changelog:
	rm -f $(CHANGELOG)

clean-test-image-cache: clean-test-image-tar-cache clean-test-image-docker-cache ## Clean test image cache

.PHONY: clear-test-image-tar-cache
clean-test-image-tar-cache:  ## Delete all test cache (built docker image tars)
	find . -type f -wholename "**/test-fixtures/cache/stereoscope-fixture-*.tar" -delete

.PHONY: clear-test-image-docker-cache
clean-test-image-docker-cache:	## Purge all test docker images
	docker images --format '{{.ID}} {{.Repository}}' | grep stereoscope-fixture- | awk '{print $$1}' | uniq | xargs -r docker rmi --force

## Halp! #################################

.PHONY: help
help:  ## Display this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
