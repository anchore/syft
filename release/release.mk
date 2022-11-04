######################
# release section
######################

# used when need to validate the goreleaser
.PHONY: snapshot
snapshot:
	LDFLAGS="$(LDFLAGS)" goreleaser release --skip-sign --skip-publish --snapshot --rm-dist --timeout 60m
