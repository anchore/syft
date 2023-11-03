RPMSDIR=rpms

ifndef RPMSDIR
    $(error RPMSDIR is not set)
endif

all: rpms

clean:
	rm -rf $(RPMSDIR)

rpms:
	mkdir -p $(RPMSDIR)
	cd $(RPMSDIR) && curl https://dl.fedoraproject.org/pub/epel/7/x86_64/Packages/a/abc-1.01-9.hg20160905.el7.x86_64.rpm -O
	cd $(RPMSDIR) && curl https://dl.fedoraproject.org/pub/epel/7/x86_64/Packages/z/zork-1.0.3-1.el7.x86_64.rpm -O

# we need a way to determine if CI should bust the test cache based on the source material
.PHONY: $(RPMSDIR).fingerprint
$(RPMSDIR).fingerprint:
	find Makefile -type f -exec sha256sum {} \; | sort | tee /dev/stderr | tee $(RPMSDIR).fingerprint
	sha256sum $(RPMSDIR).fingerprint
