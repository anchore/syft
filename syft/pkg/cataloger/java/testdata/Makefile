.DEFAULT_GOAL := default

default:
	@for dir in $(shell find . -mindepth 1 -maxdepth 1 -type d); do \
		if [ -f "$$dir/Makefile" ]; then \
			$(MAKE) -C $$dir || exit 1; \
		fi; \
	done

%:
	@for dir in $(shell find . -mindepth 1 -maxdepth 1 -type d); do \
		if [ -f "$$dir/Makefile" ]; then \
			$(MAKE) -C $$dir $@ || exit 1; \
		fi; \
	done
