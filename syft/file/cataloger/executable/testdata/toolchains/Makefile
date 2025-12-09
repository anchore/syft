# invoke all make files in subdirectories
.PHONY: all gcc clang lld mold gold rust fortran

all: gcc clang lld mold gold rust fortran

gcc:
	$(MAKE) -C gcc

clang:
	$(MAKE) -C clang

lld:
	$(MAKE) -C lld

mold:
	$(MAKE) -C mold

gold:
	$(MAKE) -C gold

rust:
	$(MAKE) -C rust

fortran:
	$(MAKE) -C fortran

%:
	@for dir in gcc clang lld mold gold rust fortran; do \
		$(MAKE) -C $$dir $@; \
	done
