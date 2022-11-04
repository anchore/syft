# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Set variables for project build
RUNTIME_IMAGE ?= gcr.io/distroless/static
GO_VERSION =$(shell go version | cut -d ' ' -f 3)
GIT_VERSION=$(shell git describe --dirty --always --tags)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = clean
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = dirty
endif
PLATFORMS=darwin linux windows
ARCHITECTURES=amd64

LDFLAGS=-buildid= -X sigs.k8s.io/release-utils/version.gitVersion=$(GIT_VERSION) \
				  -X sigs.k8s.io/release-utils/version.gitCommit=$(GIT_HASH) \
				  -X sigs.k8s.io/release-utils/version.gitTreeState=$(GIT_TREESTATE) \
				  -X sigs.k8s.io/release-utils/version.buildDate=$(BUILD_DATE) \
				  -X sigs.k8s.io/release-utils/version.goVersion=$(GO_VERSION)

SRCS = $(shell find cmd -iname "*.go") $(shell find syft -iname "*.go")

GOLANGCI_LINT_DIR = $(shell pwd)/bin
GOLANGCI_LINT_BIN = $(GOLANGCI_LINT_DIR)/golangci-lint

## Default Task
.DEFAULT_GOAL:=help

.PHONY: all lint test clean snapshot release syft help

syft: $(SRCS) ## Build syft
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/syft

##################
# help
##################

help: ## Display this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

include release/release.mk
