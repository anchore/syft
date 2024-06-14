.PHONY: *

help:
	go run -C buildtools . -l

bootstrap:
	go run -C buildtools . bootstrap

unit:
	go run -C buildtools . $@

# for some reason test does not work without an explicit target - the dir?
test:
	go run -C buildtools . $@

%:
	go run -C buildtools . $@
