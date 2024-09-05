RPMSDIR=rpms
FINGERPRINT_FILE=$(RPMSDIR).fingerprint

ifndef RPMSDIR
    $(error RPMSDIR is not set)
endif


.DEFAULT_GOAL := fixtures

# requirement 1: 'fixtures' goal to generate any and all test fixtures
fixtures: rpms

# requirement 2: 'fingerprint' goal to determine if the fixture input that indicates any existing cache should be busted
fingerprint: $(FINGERPRINT_FILE)

rpms:
	mkdir -p $(RPMSDIR)
	@# see note from https://dl.fedoraproject.org/pub/epel/7/README
	@#  ATTENTION
	@# ======================================
	@# The contents of this directory have been moved to our archives available at:
	@#
	@# http://archives.fedoraproject.org/pub/archive/epel/

	cd $(RPMSDIR) && curl -LO https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/Packages/a/abc-1.01-9.hg20160905.el7.x86_64.rpm
	cd $(RPMSDIR) && curl -LO https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/Packages/z/zork-1.0.3-1.el7.x86_64.rpm

# requirement 3: we always need to recalculate the fingerprint based on source regardless of any existing fingerprint
.PHONY: $(FINGERPRINT_FILE)
$(FINGERPRINT_FILE):
	@find Makefile -type f -exec sha256sum {} \; | sort -k2 > $(FINGERPRINT_FILE)
	@#cat $(FINGERPRINT_FILE) | sha256sum | awk '{print $$1}'

# requirement 4: 'clean' goal to remove all generated test fixtures
.PHONY: clean
clean:
	rm -rf $(RPMSDIR) $(FINGERPRINT_FILE)
