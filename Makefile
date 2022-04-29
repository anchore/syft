BIN = syft
TEMPDIR = ./.tmp
RESULTSDIR = test/results
COVER_REPORT = $(RESULTSDIR)/unit-coverage-details.txt
COVER_TOTAL = $(RESULTSDIR)/unit-coverage-summary.txt
LINTCMD = $(TEMPDIR)/golangci-lint run --tests=false --timeout=4m --config .golangci.yaml
RELEASE_CMD=$(TEMPDIR)/goreleaser release --rm-dist
SNAPSHOT_CMD=$(RELEASE_CMD) --skip-publish --snapshot
VERSION=$(shell git describe --dirty --always --tags)
COMPARE_TEST_IMAGE = centos:8.2.2004
COMPARE_DIR = ./test/compare

# formatting variables
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

# the quality gate lower threshold for unit test total % coverage (by function statements)
COVERAGE_THRESHOLD := 62

# CI cache busting values; change these if you want CI to not use previous stored cache
INTEGRATION_CACHE_BUSTER="894d8ca"
CLI_CACHE_BUSTER="e5cdfd8"
BOOTSTRAP_CACHE="c7afb99ad"

## Build variables
DISTDIR=./dist
SNAPSHOTDIR=./snapshot
OS=$(shell uname | tr '[:upper:]' '[:lower:]')
SNAPSHOT_BIN=$(shell realpath $(shell pwd)/$(SNAPSHOTDIR)/$(OS)-build_$(OS)_amd64/$(BIN))

## Variable assertions

ifndef TEMPDIR
	$(error TEMPDIR is not set)
endif

ifndef RESULTSDIR
	$(error RESULTSDIR is not set)
endif

ifndef COMPARE_DIR
	$(error COMPARE_DIR is not set)
endif

ifndef DISTDIR
	$(error DISTDIR is not set)
endif

ifndef SNAPSHOTDIR
	$(error SNAPSHOTDIR is not set)
endif

ifndef VERSION
	$(error VERSION is not set)
endif

ifndef REF_NAME
	REF_NAME = $(VERSION)
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

## Tasks

.PHONY: all
all: clean static-analysis test ## Run all linux-based checks (linting, license check, unit, integration, and linux compare tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: test
test: unit validate-cyclonedx-schema integration benchmark compare-linux cli ## Run all tests (currently unit, integration, linux compare, and cli tests)

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

.PHONY: ci-bootstrap
ci-bootstrap:
	DEBIAN_FRONTEND=noninteractive sudo apt update && sudo -E apt install -y bc jq libxml2-utils

.PHONY:
ci-bootstrap-mac:
	github_changelog_generator --version || sudo gem install github_changelog_generator

$(RESULTSDIR):
	mkdir -p $(RESULTSDIR)

$(TEMPDIR):
	mkdir -p $(TEMPDIR)

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMPDIR)
	GO111MODULE=off GOBIN=$(shell realpath $(TEMPDIR)) go get -u golang.org/x/perf/cmd/benchstat
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMPDIR)/ v1.45.0
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMPDIR)/ v0.3.0
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMPDIR)/ v0.3.0
	.github/scripts/goreleaser-install.sh -d -b $(TEMPDIR)/ v1.4.1
	GOBIN="$(shell realpath $(TEMPDIR))" go install github.com/neilpa/yajsv@v1.4.0
	GOBIN="$(shell realpath $(TEMPDIR))" go install github.com/sigstore/cosign/cmd/cosign@v1.5.1

.PHONY: bootstrap-go
bootstrap-go:
	go mod download

.PHONY: bootstrap
bootstrap: $(RESULTSDIR) bootstrap-go bootstrap-tools ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)

.PHONY: static-analysis
static-analysis: check-go-mod-tidy check-licenses lint

.PHONY: lint
lint: ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINTCMD)

	# go tooling does not play well with certain filename characters, ensure the common cases don't result in future "go get" failures
	$(eval MALFORMED_FILENAMES := $(shell find . | grep -e ':'))
	@bash -c "[[ '$(MALFORMED_FILENAMES)' == '' ]] || (printf '\nfound unsupported filename characters:\n$(MALFORMED_FILENAMES)\n\n' && false)"

.PHONY: lint-fix
lint-fix: ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(LINTCMD) --fix
	go mod tidy

.PHONY: check-licenses
check-licenses: ## Ensure transitive dependencies are compliant with the current license policy
	$(TEMPDIR)/bouncer check ./cmd/syft

check-go-mod-tidy:
	@ .github/scripts/go-mod-tidy-check.sh && echo "go.mod and go.sum are tidy!"

.PHONY: validate-cyclonedx-schema
validate-cyclonedx-schema:
	cd schema/cyclonedx && make

.PHONY: unit
unit: $(RESULTSDIR) fixtures ## Run unit tests (with coverage)
	$(call title,Running unit tests)
	go test  -coverprofile $(COVER_REPORT) $(shell go list ./... | grep -v anchore/syft/test)
	@go tool cover -func $(COVER_REPORT) | grep total |  awk '{print substr($$3, 1, length($$3)-1)}' > $(COVER_TOTAL)
	@echo "Coverage: $$(cat $(COVER_TOTAL))"
	@if [ $$(echo "$$(cat $(COVER_TOTAL)) >= $(COVERAGE_THRESHOLD)" | bc -l) -ne 1 ]; then echo "$(RED)$(BOLD)Failed coverage quality gate (> $(COVERAGE_THRESHOLD)%)$(RESET)" && false; fi

.PHONY: benchmark
benchmark: $(RESULTSDIR) ## Run benchmark tests and compare against the baseline (if available)
	$(call title,Running benchmark tests)
	go test -p 1 -run=^Benchmark -bench=. -count=5 -benchmem ./... | tee $(RESULTSDIR)/benchmark-$(REF_NAME).txt
	(test -s $(RESULTSDIR)/benchmark-main.txt && \
		$(TEMPDIR)/benchstat $(RESULTSDIR)/benchmark-main.txt $(RESULTSDIR)/benchmark-$(REF_NAME).txt || \
		$(TEMPDIR)/benchstat $(RESULTSDIR)/benchmark-$(REF_NAME).txt) \
			| tee $(RESULTSDIR)/benchstat.txt

.PHONY: show-benchstat
show-benchstat:
	@cat $(RESULTSDIR)/benchstat.txt

# note: this is used by CI to determine if the install test fixture cache (docker image tars) should be busted
install-fingerprint:
	cd test/install && \
		make cache.fingerprint

install-test: $(SNAPSHOTDIR)
	cd test/install && \
		make

install-test-cache-save: $(SNAPSHOTDIR)
	cd test/install && \
		make save

install-test-cache-load: $(SNAPSHOTDIR)
	cd test/install && \
		make load

install-test-ci-mac: $(SNAPSHOTDIR)
	cd test/install && \
		make ci-test-mac

.PHONY: integration
integration: ## Run integration tests
	$(call title,Running integration tests)
	go test -v ./test/integration

# note: this is used by CI to determine if the integration test fixture cache (docker image tars) should be busted
integration-fingerprint:
	$(call title,Integration test fixture fingerprint)
	find test/integration/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | tee /dev/stderr | md5sum | tee test/integration/test-fixtures/cache.fingerprint && echo "$(INTEGRATION_CACHE_BUSTER)" >> test/integration/test-fixtures/cache.fingerprint

.PHONY: java-packages-fingerprint
java-packages-fingerprint:
	$(call title,Java test fixture fingerprint)
	cd syft/pkg/cataloger/java/test-fixtures/java-builds && \
		make packages.fingerprint

.PHONY: go-binaries-fingerprint
go-binaries-fingerprint:
	$(call title,Go binaries test fixture fingerprint)
	cd syft/pkg/cataloger/golang/test-fixtures/archs && \
		make binaries.fingerprint

.PHONY: fixtures
fixtures:
	$(call title,Generating test fixtures)
	cd syft/pkg/cataloger/java/test-fixtures/java-builds && make

.PHONY: generate-json-schema
generate-json-schema:  ## Generate a new json schema
	cd schema/json && go run generate.go

.PHONY: generate-license-list
generate-license-list: ## Generate an updated spdx license list
	go generate ./internal/spdxlicense/...
	gofmt -s -w ./internal/spdxlicense

.PHONY: build
build: $(SNAPSHOTDIR) ## Build release snapshot binaries and packages

$(SNAPSHOTDIR): ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	# build release snapshots
	bash -c "SKIP_SIGNING=true $(SNAPSHOT_CMD) --skip-sign --config $(TEMPDIR)/goreleaser.yaml"

.PHONY: snapshot-with-signing
snapshot-with-signing: ## Build snapshot release binaries and packages (with dummy signing)
	$(call title,Building snapshot artifacts (+ signing))

	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	rm -f .github/scripts/apple-signing/log/*.txt

	# build release snapshots
	bash -c "$(SNAPSHOT_CMD) --config $(TEMPDIR)/goreleaser.yaml || (cat .github/scripts/apple-signing/log/*.txt && false)"

	# remove the keychain with the trusted self-signed cert automatically
	.github/scripts/apple-signing/cleanup.sh

# note: we cannot clean the snapshot directory since the pipeline builds the snapshot separately
.PHONY: compare-mac
compare-mac: $(RESULTSDIR) $(SNAPSHOTDIR) ## Run compare tests on build snapshot binaries and packages (Mac)
	$(call title,Running compare test: Run on Mac)
	$(COMPARE_DIR)/mac.sh \
			$(SNAPSHOTDIR) \
			$(COMPARE_DIR) \
			$(COMPARE_TEST_IMAGE) \
			$(RESULTSDIR)

# note: we cannot clean the snapshot directory since the pipeline builds the snapshot separately
.PHONY: compare-linux
compare-linux: compare-test-deb-package-install compare-test-rpm-package-install ## Run compare tests on build snapshot binaries and packages (Linux)

.PHONY: compare-test-deb-package-install
compare-test-deb-package-install: $(RESULTSDIR) $(SNAPSHOTDIR)
	$(call title,Running compare test: DEB install)
	$(COMPARE_DIR)/deb.sh \
			$(SNAPSHOTDIR) \
			$(COMPARE_DIR) \
			$(COMPARE_TEST_IMAGE) \
			$(RESULTSDIR)

.PHONY: compare-test-rpm-package-install
compare-test-rpm-package-install: $(RESULTSDIR) $(SNAPSHOTDIR)
	$(call title,Running compare test: RPM install)
	$(COMPARE_DIR)/rpm.sh \
			$(SNAPSHOTDIR) \
			$(COMPARE_DIR) \
			$(COMPARE_TEST_IMAGE) \
			$(RESULTSDIR)

# note: this is used by CI to determine if the integration test fixture cache (docker image tars) should be busted
cli-fingerprint:
	$(call title,CLI test fixture fingerprint)
	find test/cli/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum | tee test/cli/test-fixtures/cache.fingerprint && echo "$(CLI_CACHE_BUSTER)" >> test/cli/test-fixtures/cache.fingerprint

.PHONY: cli
cli: $(SNAPSHOTDIR) ## Run CLI tests
	chmod 755 "$(SNAPSHOT_BIN)"
	$(SNAPSHOT_BIN) version
	SYFT_BINARY_LOCATION='$(SNAPSHOT_BIN)' \
		go test -count=1 -timeout=15m -v ./test/cli

.PHONY: changelog
changelog: clean-changelog CHANGELOG.md
	@docker run -it --rm \
		-v $(shell pwd)/CHANGELOG.md:/CHANGELOG.md \
		rawkode/mdv \
			-t 748.5989 \
			/CHANGELOG.md

CHANGELOG.md:
	$(TEMPDIR)/chronicle -vv > CHANGELOG.md

.PHONY: release
release: clean-dist CHANGELOG.md  ## Build and publish final binaries and packages. Intended to be run only on macOS.
	$(call title,Publishing release artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(DISTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	rm -f .github/scripts/apple-signing/log/*.txt

	# note: notarization cannot be done in parallel, thus --parallelism 1
	bash -c "\
		$(RELEASE_CMD) \
			--config $(TEMPDIR)/goreleaser.yaml \
			--parallelism 1 \
			--release-notes <(cat CHANGELOG.md)\
				 || (cat .github/scripts/apple-signing/log/*.txt && false)"

	cat .github/scripts/apple-signing/log/*.txt

	# TODO: turn this into a post-release hook
	# upload the version file that supports the application version update check (excluding pre-releases)
	.github/scripts/update-version-file.sh "$(DISTDIR)" "$(VERSION)"


.PHONY: clean
clean: clean-dist clean-snapshot clean-test-image-cache ## Remove previous builds, result reports, and test cache
	$(call safe_rm_rf_children,$(RESULTSDIR))

.PHONY: clean-snapshot
clean-snapshot:
	$(call safe_rm_rf,$(SNAPSHOTDIR))
	rm -f $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-dist
clean-dist: clean-changelog
	$(call safe_rm_rf,$(DISTDIR))
	rm -f $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-changelog
clean-changelog:
	rm -f CHANGELOG.md

clean-test-image-cache: clean-test-image-tar-cache clean-test-image-docker-cache

.PHONY: clear-test-image-tar-cache
clean-test-image-tar-cache: ## Delete all test cache (built docker image tars)
	find . -type f -wholename "**/test-fixtures/cache/stereoscope-fixture-*.tar" -delete

.PHONY: clear-test-image-docker-cache
clean-test-image-docker-cache: ## Purge all test docker images
	docker images --format '{{.ID}} {{.Repository}}' | grep stereoscope-fixture- | awk '{print $$1}' | uniq | xargs docker rmi --force

.PHONY: show-test-image-cache
show-test-image-cache: ## Show all docker and image tar cache
	$(call title,Docker daemon cache)
	@docker images --format '{{.ID}} {{.Repository}}:{{.Tag}}' | grep stereoscope-fixture- | sort

	$(call title,Tar cache)
	@find . -type f -wholename "**/test-fixtures/cache/stereoscope-fixture-*.tar" | sort

.PHONY: show-test-snapshots
show-test-snapshots: ## Show all test snapshots
	$(call title,Test snapshots)
	@find . -type f -wholename "**/test-fixtures/snapshot/*" | sort
