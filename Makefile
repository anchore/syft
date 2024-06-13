.PHONY: help
help:
	@go run -C buildtools . -l

.PHONY: %
%:
	@go run -C buildtools . $@
