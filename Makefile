# `test` and `snapshot` have matching directory names in this repo, so make would
# refuse to run them without an explicit .PHONY (Nothing to be done for ...).
.PHONY: test snapshot
test:
	@go run -C .make . test

snapshot:
	@go run -C .make . snapshot

.PHONY: *
.DEFAULT_GOAL: make-default

make-default:
	@go run -C .make .

.DEFAULT:
%:
	@go run -C .make . $@
