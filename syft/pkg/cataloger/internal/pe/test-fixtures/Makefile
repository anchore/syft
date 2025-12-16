FINGERPRINT_FILE=cache.fingerprint

.DEFAULT_GOAL := fixtures

# requirement 1: 'fixtures' goal to generate any and all test fixtures
fixtures:
	@echo "nothing to do"

# requirement 2: 'fingerprint' goal to determine if cache should be busted
fingerprint: $(FINGERPRINT_FILE)

# requirement 3: always recalculate fingerprint based on source
.PHONY: $(FINGERPRINT_FILE)
$(FINGERPRINT_FILE):
	@find Makefile **/Dockerfile **/src/** -type f -exec sha256sum {} \; | sort -k2 > $(FINGERPRINT_FILE)

# requirement 4: 'clean' goal to remove generated test fixtures
clean:
	rm -f $(FINGERPRINT_FILE)
