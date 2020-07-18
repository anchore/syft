TEMPDIR = ./.tmp
RESULTSDIR = $(TEMPDIR)/results
COVER_REPORT = $(RESULTSDIR)/cover.report
COVER_TOTAL = $(RESULTSDIR)/cover.total
LICENSES_REPORT = $(RESULTSDIR)/licenses.json
LINTCMD = $(TEMPDIR)/golangci-lint run --tests=false --config .golangci.yaml
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)
# the quality gate lower threshold for unit test total % coverage (by function statements)
COVERAGE_THRESHOLD := 72

ifndef TEMPDIR
    $(error TEMPDIR is not set)
endif

ifndef RESULTSDIR
    $(error RESULTSDIR is not set)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

## Build variables
DISTDIR=./dist
VERSIONPATH=$(DISTDIR)/VERSION
GITTREESTATE=$(if $(shell git status --porcelain),dirty,clean)

ifeq "$(strip $(VERSION))" ""
 override VERSION = $(shell git describe --always --tags --dirty)
endif

.PHONY: all bootstrap lint lint-fix unit coverage integration check-pipeline clear-cache help test compare release clean

all: lint check-licenses test ## Run all checks (linting, license check, unit tests, and integration tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

compare:
	@cd comparison && make

test: unit integration ## Run all tests (currently unit & integration)

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

ci-bootstrap: ci-lib-dependencies bootstrap
	sudo apt install -y bc

ci-lib-dependencies:
	# libdb5.3-dev and libssl-dev are required for Berkeley DB C bindings for RPM DB support
	sudo apt install -y libdb5.3-dev libssl-dev

bootstrap: ## Download and install all project dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Downloading dependencies)
	# prep temp dirs
	mkdir -p $(TEMPDIR)
	mkdir -p $(RESULTSDIR)
	# install project dependencies
	go mod download
	# install golangci-lint
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMPDIR)/ v1.26.0
	# install bouncer
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMPDIR)/ v0.1.0
	# install goreleaser
	curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | sh -s -- -b $(TEMPDIR)/ v0.140.0

lint: ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"
	$(LINTCMD)

lint-fix: ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(LINTCMD) --fix

unit: ## Run unit tests (with coverage)
	$(call title,Running unit tests)
	go test --race -coverprofile $(COVER_REPORT) ./...
	@go tool cover -func $(COVER_REPORT) | grep total |  awk '{print substr($$3, 1, length($$3)-1)}' > $(COVER_TOTAL)
	@echo "Coverage: $$(cat $(COVER_TOTAL))"
	@if [ $$(echo "$$(cat $(COVER_TOTAL)) >= $(COVERAGE_THRESHOLD)" | bc -l) -ne 1 ]; then echo "$(RED)$(BOLD)Failed coverage quality gate (> $(COVERAGE_THRESHOLD)%)$(RESET)" && false; fi

integration: ## Run integration tests
	$(call title,Running integration tests)
	go test -v -tags=integration ./integration

integration/test-fixtures/tar-cache.key, integration-fingerprint:
	find integration/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum | tee integration/test-fixtures/tar-cache.fingerprint

java-packages-fingerprint:
	@cd imgbom/cataloger/java/test-fixtures/java-builds && \
	make packages.fingerprint

clear-test-cache: ## Delete all test cache (built docker image tars)
	find . -type f -wholename "**/test-fixtures/tar-cache/*.tar" -delete

check-pipeline: ## Run local CircleCI pipeline locally (sanity check)
	$(call title,Check pipeline)
	# note: this is meant for local development & testing of the pipeline, NOT to be run in CI
	mkdir -p $(TEMPDIR)
	circleci config process .circleci/config.yml > .tmp/circleci.yml
	circleci local execute -c .tmp/circleci.yml --job "Static Analysis"
	circleci local execute -c .tmp/circleci.yml --job "Unit & Integration Tests (go-latest)"
	@printf '$(SUCCESS)Pipeline checks pass!$(RESET)\n'


build: ## Build snapshot release binaries and packages
	BUILD_GIT_TREE_STATE=$(GITTREESTATE) \
	$(TEMPDIR)/goreleaser build --rm-dist --snapshot
	echo "$(VERSION)" > $(VERSIONPATH)

# TODO: this is not releasing yet
release: ## Build and publish final binaries and packages
	BUILD_GIT_TREE_STATE=$(GITTREESTATE) \
	$(TEMPDIR)/goreleaser --skip-publish --rm-dist --snapshot
	echo "$(VERSION)" > $(VERSIONPATH)

check-licenses:
	$(TEMPDIR)/bouncer list -o json | tee $(LICENSES_REPORT)
	$(TEMPDIR)/bouncer check

clean:
	rm -rf dist/ $(RESULTSDIR)/*
