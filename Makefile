BIN = syft
TEMPDIR = ./.tmp
RESULTSDIR = test/results
COVER_REPORT = $(RESULTSDIR)/unit-coverage-details.txt
COVER_TOTAL = $(RESULTSDIR)/unit-coverage-summary.txt
LINTCMD = $(TEMPDIR)/golangci-lint run --tests=false --config .golangci.yaml
ACC_TEST_IMAGE = centos:8.2.2004
ACC_DIR = ./test/acceptance
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)
# the quality gate lower threshold for unit test total % coverage (by function statements)
COVERAGE_THRESHOLD := 70
# CI cache busting values; change these if you want CI to not use previous stored cache
INTEGRATION_CACHE_BUSTER="88738d2f"
CLI_CACHE_BUSTER="789bacdf"
BOOTSTRAP_CACHE="c7afb99ad"

## Build variables
DISTDIR=./dist
SNAPSHOTDIR=./snapshot
GITTREESTATE=$(if $(shell git status --porcelain),dirty,clean)
OS := $(shell uname)

ifeq ($(OS),Darwin)
	SNAPSHOT_CMD=$(shell realpath $(shell pwd)/$(SNAPSHOTDIR)/$(BIN)-macos_darwin_amd64/$(BIN))
else
	SNAPSHOT_CMD=$(shell realpath $(shell pwd)/$(SNAPSHOTDIR)/$(BIN)_linux_amd64/$(BIN))
endif

ifeq "$(strip $(VERSION))" ""
 override VERSION = $(shell git describe --always --tags --dirty)
endif

# used to generate the changelog from the second to last tag to the current tag (used in the release pipeline when the release tag is in place)
LAST_TAG := $(shell git describe --abbrev=0 --tags $(shell git rev-list --tags --max-count=1))
SECOND_TO_LAST_TAG := $(shell git describe --abbrev=0 --tags $(shell git rev-list --tags --skip=1 --max-count=1))

## Variable assertions

ifndef TEMPDIR
	$(error TEMPDIR is not set)
endif

ifndef RESULTSDIR
	$(error RESULTSDIR is not set)
endif

ifndef ACC_DIR
	$(error ACC_DIR is not set)
endif

ifndef DISTDIR
	$(error DISTDIR is not set)
endif

ifndef SNAPSHOTDIR
	$(error SNAPSHOTDIR is not set)
endif

ifndef REF_NAME
	REF_NAME = $(VERSION)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

## Tasks

.PHONY: all
all: clean static-analysis test ## Run all linux-based checks (linting, license check, unit, integration, and linux acceptance tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: test
test: unit validate-cyclonedx-schema integration benchmark acceptance-linux cli ## Run all tests (currently unit, integration, linux acceptance, and cli tests)

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
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMPDIR)/ v1.26.0
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMPDIR)/ v0.2.0
	curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | sh -s -- -b $(TEMPDIR)/ v0.160.0

.PHONY: bootstrap-go
bootstrap-go:
	go mod download
	go mod tidy # note: it is important that the go.sum is kept in a consistent state at all times (especially during release)

.PHONY: bootstrap
bootstrap: $(RESULTSDIR) bootstrap-go bootstrap-tools ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)

.PHONY: static-analysis
static-analysis: lint check-licenses

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

.PHONY: check-licenses
check-licenses:
	$(TEMPDIR)/bouncer check

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

.PHONY: integration
integration: ## Run integration tests
	$(call title,Running integration tests)

	go test -v ./test/integration

# note: this is used by CI to determine if the integration test fixture cache (docker image tars) should be busted
integration-fingerprint:
	find test/integration/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum | tee test/integration/test-fixtures/cache.fingerprint && echo "$(INTEGRATION_CACHE_BUSTER)" >> test/integration/test-fixtures/cache.fingerprint

.PHONY: java-packages-fingerprint
java-packages-fingerprint:
	@cd syft/pkg/cataloger/java/test-fixtures/java-builds && \
	make packages.fingerprint

.PHONY: fixtures
fixtures:
	$(call title,Generating test fixtures)
	cd syft/pkg/cataloger/java/test-fixtures/java-builds && make

.PHONY: generate-json-schema
generate-json-schema:  ## Generate a new json schema
	cd schema/json && go run generate.go

.PHONY: build
build: $(SNAPSHOTDIR) ## Build release snapshot binaries and packages

$(SNAPSHOTDIR): ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)
	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	# build release snapshots
	BUILD_GIT_TREE_STATE=$(GITTREESTATE) \
	$(TEMPDIR)/goreleaser release --skip-publish --skip-sign --rm-dist --snapshot --config $(TEMPDIR)/goreleaser.yaml

# note: we cannot clean the snapshot directory since the pipeline builds the snapshot separately
.PHONY: acceptance-mac
acceptance-mac: $(RESULTSDIR) $(SNAPSHOTDIR) ## Run acceptance tests on build snapshot binaries and packages (Mac)
	$(call title,Running acceptance test: Run on Mac)
	$(ACC_DIR)/mac.sh \
			$(SNAPSHOTDIR) \
			$(ACC_DIR) \
			$(ACC_TEST_IMAGE) \
			$(RESULTSDIR)

# note: we cannot clean the snapshot directory since the pipeline builds the snapshot separately
.PHONY: acceptance-linux
acceptance-linux: acceptance-test-deb-package-install acceptance-test-rpm-package-install ## Run acceptance tests on build snapshot binaries and packages (Linux)

.PHONY: acceptance-test-deb-package-install
acceptance-test-deb-package-install: $(RESULTSDIR) $(SNAPSHOTDIR)
	$(call title,Running acceptance test: DEB install)
	$(ACC_DIR)/deb.sh \
			$(SNAPSHOTDIR) \
			$(ACC_DIR) \
			$(ACC_TEST_IMAGE) \
			$(RESULTSDIR)

.PHONY: acceptance-test-rpm-package-install
acceptance-test-rpm-package-install: $(RESULTSDIR) $(SNAPSHOTDIR)
	$(call title,Running acceptance test: RPM install)
	$(ACC_DIR)/rpm.sh \
			$(SNAPSHOTDIR) \
			$(ACC_DIR) \
			$(ACC_TEST_IMAGE) \
			$(RESULTSDIR)

# note: this is used by CI to determine if the integration test fixture cache (docker image tars) should be busted
cli-fingerprint:
	find test/cli/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum | tee test/cli/test-fixtures/cache.fingerprint && echo "$(CLI_CACHE_BUSTER)" >> test/cli/test-fixtures/cache.fingerprint

.PHONY: cli
cli: $(SNAPSHOTDIR) ## Run CLI tests
	chmod 755 "$(SNAPSHOT_CMD)"
	$(SNAPSHOT_CMD) version
	SYFT_BINARY_LOCATION='$(SNAPSHOT_CMD)' \
		go test -count=1 -v ./test/cli

.PHONY: changlog-release
changelog-release:
	@echo "Last tag: $(SECOND_TO_LAST_TAG)"
	@docker run --rm \
		-v "$(shell pwd)":/usr/local/src/your-app \
		ferrarimarco/github-changelog-generator \
		--user anchore \
		--project $(BIN) \
		-t ${GITHUB_TOKEN} \
		--exclude-labels 'duplicate,question,invalid,wontfix,size:small,size:medium,size:large,size:x-large' \
		--no-pr-wo-labels \
		--no-issues-wo-labels \
		--since-tag $(SECOND_TO_LAST_TAG)

	@printf '\n$(BOLD)$(CYAN)Release $(VERSION) Changelog$(RESET)\n\n'
	@cat CHANGELOG.md

.PHONY: changelog-unreleased
changelog-unreleased: ## show the current changelog that will be produced on the next release (note: requires GITHUB_TOKEN set)
	@docker run -it --rm \
		-v "$(shell pwd)":/usr/local/src/your-app \
		ferrarimarco/github-changelog-generator \
		--user anchore \
		--project $(BIN) \
		-t ${GITHUB_TOKEN} \
		--exclude-labels 'duplicate,question,invalid,wontfix,size:small,size:medium,size:large,size:x-large' \
		--since-tag $(LAST_TAG)

	@printf '\n$(BOLD)$(CYAN)Unreleased Changes (closed PRs and issues will not be in the final changelog)$(RESET)\n'

	@docker run -it --rm \
		-v $(shell pwd)/CHANGELOG.md:/CHANGELOG.md \
		rawkode/mdv \
			-t 748.5989 \
			/CHANGELOG.md

.PHONY: release
release: clean-dist changelog-release ## Build and publish final binaries and packages. Intended to be run only on macOS.
	$(call title,Publishing release artifacts)

	# Prepare for macOS-specific signing process
	.github/scripts/mac-prepare-for-signing.sh

	# login to docker
	# note: the previous step creates a new keychain, so it is important to reauth into docker.io
	@echo $${DOCKER_PASSWORD} | docker login docker.io -u $${DOCKER_USERNAME}  --password-stdin

	# create a config with the dist dir overridden
	echo "dist: $(DISTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	# release (note the version transformation from v0.7.0 --> 0.7.0)
	bash -c "\
		BUILD_GIT_TREE_STATE=$(GITTREESTATE) \
		VERSION=$(VERSION:v%=%) \
		$(TEMPDIR)/goreleaser \
			--rm-dist \
			--config $(TEMPDIR)/goreleaser.yaml \
			--release-notes <(cat CHANGELOG.md)"

	# verify checksum signatures
	.github/scripts/verify-signature.sh "$(DISTDIR)"

	# upload the version file that supports the application version update check (excluding pre-releases)
	.github/scripts/update-version-file.sh "$(DISTDIR)" "$(VERSION)"


.PHONY: clean
clean: clean-dist clean-snapshot clean-test-image-cache ## Remove previous builds, result reports, and test cache
	rm -rf $(RESULTSDIR)/*

.PHONY: clean-snapshot
clean-snapshot:
	rm -rf $(SNAPSHOTDIR) $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-dist
clean-dist:
	rm -rf $(DISTDIR) $(TEMPDIR)/goreleaser.yaml

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