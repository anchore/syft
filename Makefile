%:
	@cd buildtools && go run . $@

.PHONY: help
help:
	@cd buildtools && go run . help
