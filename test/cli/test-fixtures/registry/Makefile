all: build start

.PHONY: stop
stop:
	docker kill registry

.PHONY: build
build:
	docker build -t localhost:5000/attest:latest .

.PHONY: start
start:
	docker run --rm \
				-d \
				--name registry \
				-it \
				--privileged \
				-p 5000:5000 \
				registry:2.8

.PHONY: push
push:
	docker push localhost:5000/attest:latest
