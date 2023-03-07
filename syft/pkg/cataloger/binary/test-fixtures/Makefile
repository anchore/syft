.PHONY: all
all: \
	classifiers/dynamic/python-binary-shared-lib-3.11 \
	classifiers/dynamic/python-binary-shared-lib-redhat-3.9 \
	classifiers/dynamic/python-binary-with-version-3.9

classifiers/dynamic/python-binary-shared-lib-3.11:
	$(eval $@_image := "python:3.11-slim@sha256:0b106e1d2bf485c2a41474bc9cd5103e9eea4e179f40f10741b53b127059221e")
	./get-image-file.sh $($@_image) \
		/usr/local/bin/python3.11 \
		$@/python3
	./get-image-file.sh $($@_image) \
		/usr/local/lib/libpython3.11.so.1.0 \
		$@/libpython3.11.so.1.0

classifiers/dynamic/python-binary-shared-lib-redhat-3.9:
	$(eval $@_image := "registry.access.redhat.com/ubi8/python-39@sha256:f3cf958b96ce016b63e3e163e488f52e42891304dafef5a0811563f22e3cbad0")
	./get-image-file.sh $($@_image) \
		/usr/bin/python3.9 \
		$@/python3.9
	./get-image-file.sh $($@_image) \
		/usr/lib64/libpython3.9.so.1.0 \
		$@/libpython3.9.so.1.0

classifiers/dynamic/python-binary-with-version-3.9:
	$(eval $@_image := "python:3.9.16-bullseye@sha256:93fb93c461a2e47a2176706fad1f39eaacd5dd40e19c0b018699a28c03eb2e2a")
	./get-image-file.sh $($@_image) \
		/usr/bin/python3.9 \
		$@/python3.9

.PHONY: clean
clean:
	rm -rf classifiers/dynamic

.PHONY: cache.fingerprint
cache.fingerprint: # for CI
	$(title,Install test fixture fingerprint)
	@find ./classifiers/dynamic/* -type f -exec md5sum {} + | awk '{print $1}' | sort | tee /dev/stderr | md5sum | tee cache.fingerprint >> cache.fingerprint
