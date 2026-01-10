# invoke all make files in subdirectories
.PHONY: all gcc clang

all: gcc clang

gcc:
	$(MAKE) -C gcc

clang:
	$(MAKE) -C clang

%:
	@for dir in gcc clang; do \
		$(MAKE) -C $$dir $@; \
	done
