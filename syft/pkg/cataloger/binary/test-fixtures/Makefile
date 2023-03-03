.PHONY: all
all: classifiers/dynamic/python-binary-shared-lib-3.11

classifiers/dynamic/python-binary-shared-lib-3.11:
	$(title,Download python shared library binaries v3.11)
	$(eval $@_image := "python:3.11-slim@sha256:0b106e1d2bf485c2a41474bc9cd5103e9eea4e179f40f10741b53b127059221e")
	./get-docker-file.sh $($@_image) \
		/usr/local/bin/python3.11 \
		$@/python3
	./get-docker-file.sh $($@_image) \
		/usr/local/lib/libpython3.11.so.1.0 \
		$@/libpython3.11.so.1.0

.PHONY: clean
clean:
	rm -rf classifiers/dynamic

.PHONY: cache.fingerprint
cache.fingerprint: # for CI
	$(title,Install test fixture fingerprint)
	@find ./classifiers/dynamic/* -type f -exec md5sum {} + | awk '{print $1}' | sort | tee /dev/stderr | md5sum | tee cache.fingerprint >> cache.fingerprint
