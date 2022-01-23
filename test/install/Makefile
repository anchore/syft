NAME=syft
IMAGE_NAME=$(NAME)-install.sh-env
ENVS=./environments
DOCKER_RUN=docker run --rm -t -w /project/test/install -v $(shell pwd)/../../:/project
UNIT=make unit-local

# acceptance testing is running the current install.sh against the latest release. Note: this could be a problem down
# the line if there are breaking changes made that don't align with the latest release (but will be OK with the next
# release)
acceptance=sh -c '../../install.sh -b /usr/local/bin  && syft version'

# CI cache busting values; change these if you want CI to not use previous stored cache
INSTALL_TEST_CACHE_BUSTER=894d8ca

define title
    @printf '\n≡≡≡[ $(1) ]≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡\n'
endef

.PHONY: test
test: unit acceptance

.PHONY: ci-test-mac
ci-test-mac: unit-local acceptance-local

# note: do not add acceptance-local to this list
acceptance: acceptance-ubuntu-20.04 acceptance-alpine-3.6 acceptance-busybox-1.35

unit: unit-ubuntu-20.04

unit-local:
	$(call title,unit tests)
	@for f in $(shell ls *_test.sh); do echo "Running unit test suite '$${f}'"; bash $${f} || exit 1; done

acceptance-local:
	$(acceptance)

## UBUNTU #######################################################

acceptance-ubuntu-20.04: ubuntu-20.04
	$(call title,ubuntu:20.04 - acceptance)
	$(DOCKER_RUN) $(NAME)-install.sh-env:ubuntu-20.04 \
		$(acceptance)

unit-ubuntu-20.04: ubuntu-20.04
	$(call title,ubuntu:20.04 - unit)
	$(DOCKER_RUN) $(NAME)-install.sh-env:ubuntu-20.04 \
		$(UNIT)

ubuntu-20.04:
	$(call title,ubuntu:20.04 - build environment)
	docker build -t $(IMAGE_NAME):ubuntu-20.04 -f $(ENVS)/Dockerfile-ubuntu-20.04 .

## ALPINE #######################################################

# note: unit tests cannot be run with sh (alpine dosn't have bash by default)

acceptance-alpine-3.6: alpine-3.6
	$(call title,alpine:3.6 - acceptance)
	$(DOCKER_RUN) $(NAME)-install.sh-env:alpine-3.6 \
		$(acceptance)

alpine-3.6:
	$(call title,alpine:3.6 - build environment)
	docker build -t $(IMAGE_NAME):alpine-3.6 -f $(ENVS)/Dockerfile-alpine-3.6 .

## BUSYBOX #######################################################

# note: unit tests cannot be run with sh (busybox dosn't have bash by default)

# note: busybox by default will not have cacerts, so you will get TLS warnings (we want to test under these conditions)

acceptance-busybox-1.35:
	$(call title,busybox-1.35 - acceptance)
	$(DOCKER_RUN) busybox:1.35 \
		$(acceptance)
	@echo "\n*** test note: you should see syft spit out a 'x509: certificate signed by unknown authority' error --this is expected ***"

## For CI ########################################################

.PHONY: cache.fingerprint
cache.fingerprint:
	$(call title,Install test fixture fingerprint)
	@find ./environments/* -type f -exec md5sum {} + | awk '{print $1}' | sort | tee /dev/stderr | md5sum | tee cache.fingerprint && echo "$(INSTALL_TEST_CACHE_BUSTER)" >> cache.fingerprint
