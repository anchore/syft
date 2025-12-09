# invoke all make files in subdirectories
.PHONY: all gcc clang lld mold gold rust fortran gdc gccgo gnat

all: gcc clang lld mold gold rust fortran gdc gccgo gnat

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

gdc:
	$(MAKE) -C gdc

gccgo:
	$(MAKE) -C gccgo

gnat:
	$(MAKE) -C gnat

%:
	@for dir in gcc clang lld mold gold rust fortran gdc gccgo gnat; do \
		$(MAKE) -C $$dir $@; \
	done
