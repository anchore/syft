all:

# we need a way to determine if CI should bust the test cache based on the source material
.PHONY: cache.fingerprint
cache.fingerprint:
	find Makefile **/Dockerfile -type f -exec sha256sum {} \; | sort | tee /dev/stderr | tee cache.fingerprint
	sha256sum cache.fingerprint
