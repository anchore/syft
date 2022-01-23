NAME=syft
IMAGE_NAME=$(NAME)-install.sh-env
ENVS=./environments
DOCKER_RUN=docker run --rm -t -w /project/test/install -v $(shell pwd)/../../:/project
UNIT=make unit-local
INTEGRATION=sh -c '../../install.sh -b /usr/local/bin  && syft version'

define title
    @printf '≡≡[ $(1) ]≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡\n'
endef

.PHONY: test
test: unit integration

# note: do not add integration-local to this list
integration: integration-ubuntu-20.04 integration-alpine-3.6 integration-busybox-1.35

unit: unit-ubuntu-20.04

unit-local:
	$(call title,unit tests)
	@for f in $(shell ls *_test.sh); do echo "Running unit test suite '$${f}'"; bash $${f} || exit 1; done

integration-local:
	$(INTEGRATION)

## UBUNTU #######################################################

integration-ubuntu-20.04: ubuntu-20.04
	$(call title,ubuntu:20.04 - integration)
	$(DOCKER_RUN) $(NAME)-install.sh-env:ubuntu-20.04 \
		$(INTEGRATION)

unit-ubuntu-20.04: ubuntu-20.04
	$(call title,ubuntu:20.04 - unit)
	$(DOCKER_RUN) $(NAME)-install.sh-env:ubuntu-20.04 \
		$(UNIT)

ubuntu-20.04:
	$(call title,ubuntu:20.04 - build environment)
	docker build -t $(IMAGE_NAME):ubuntu-20.04 -f $(ENVS)/Dockerfile-ubuntu-20.04 .

## ALPINE #######################################################

# note: unit tests cannot be run with sh (alpine dosn't have bash by default)

integration-alpine-3.6: alpine-3.6
	$(call title,alpine:3.6 - integration)
	$(DOCKER_RUN) $(NAME)-install.sh-env:alpine-3.6 \
		$(INTEGRATION)

alpine-3.6:
	$(call title,alpine:3.6 - build environment)
	docker build -t $(IMAGE_NAME):alpine-3.6 -f $(ENVS)/Dockerfile-alpine-3.6 .

## BUSYBOX #######################################################

# note: unit tests cannot be run with sh (busybox dosn't have bash by default)

# note: busybox by default will not have cacerts, so you will get TLS warnings (we want to test under these conditions)

integration-busybox-1.35:
	$(call title,busybox-1.35 - integration)
	$(DOCKER_RUN) busybox:1.35 \
		$(INTEGRATION)
