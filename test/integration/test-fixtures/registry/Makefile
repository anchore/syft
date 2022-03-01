all: start

.PHONY: stop
stop:
	docker kill registry

.PHONY: start
start:
	docker run --rm \
				-d \
				--name registry \
				-it \
				--privileged \
				-p 5010:5010 \
				registry:2.8
