all: build start push

.PHONY: stop
stop:
	docker kill registry

.PHONY: build
build:
	docker build -t localhost:2222/attest:latest .

.PHONY: start
start:
	docker run --rm \
				-d \
				--name registry \
				-it \
				--privileged \
				-p 2222:5000 \
				registry:2.8
.PHONY: push
push:
	docker push localhost:2222/attest:latest
