### GCC Options ############################################
CANARY := -fstack-protector
NO_CANARY := -fno-stack-protector

SHARED_OBJ := -shared

RELRO := -z relro -z now
PARTIAL_RELRO := -z relro
NO_RELRO := -z norelro

NX := -z noexecstack
NO_NX := -z execstack

PIE := -fpic -pie
NO_PIE := -no-pie

# deprecated
RPATH := -Wl,--disable-new-dtags,-rpath,./libs

# replaces RPATH (thus us mutually exclusive with it)
RUNPATH :=  -Wl,-rpath,./libs

GCCFLAGS := -g 

### Clang Options ############################################

SAFE_STACK := -fsanitize=safe-stack

CFI := -flto -fvisibility=hidden -fsanitize=cfi

FORTIFY := -O2 -D_FORTIFY_SOURCE=2

### Common Options ############################################

SRC := main.c
LIB_SRC := lib.c
BIN := ../bin

BINS :=        $(BIN)/no_protection $(BIN)/with_nx $(BIN)/pie_false_positive.so $(BIN)/with_pie $(BIN)/with_canary $(BIN)/with_relro $(BIN)/with_partial_relro $(BIN)/with_rpath $(BIN)/with_runpath $(BIN)/with_safestack $(BIN)/with_cfi $(BIN)/with_fortify $(BIN)/protected
#.PHONY: verify $(BIN)/no_protection $(BIN)/with_nx $(BIN)/pie_false_positive.so $(BIN)/with_pie $(BIN)/with_canary $(BIN)/with_relro $(BIN)/with_partial_relro $(BIN)/with_rpath $(BIN)/with_runpath $(BIN)/with_safestack $(BIN)/with_cfi $(BIN)/with_fortify $(BIN)/protected
.PHONY: verify clean all

all: $(BINS)


$(BIN)/no_protection : $(SRC)
	gcc $< -o $@ $(GCCFLAGS) $(NO_CANARY) $(NO_NX) $(NO_RELRO) $(NO_PIE) $(RUNPATH) 

$(BIN)/with_nx : $(SRC)
	gcc $< -o $@ $(GCCFLAGS) $(NO_CANARY) $(NX) $(NO_RELRO) $(NO_PIE) 

$(BIN)/pie_false_positive.so: $(LIB_SRC)
	gcc $< -c -Wall -Werror -fpic $(LIB_SRC)
	gcc -shared -o $@ lib.o ; rm lib.o

$(BIN)/with_pie: $(SRC)
	gcc $< -o $@ $(GCCFLAGS) $(NO_CANARY) $(NO_NX) $(NO_RELRO) $(PIE)

$(BIN)/with_canary: $(SRC)
	gcc $< -o $@ $(GCCFLAGS) $(CANARY) $(NO_NX) $(NO_RELRO) $(NO_PIE) 

$(BIN)/with_relro: $(SRC)
	gcc $< -o $@ $(GCCFLAGS) $(NO_CANARY) $(NO_NX) $(RELRO) $(NO_PIE)

$(BIN)/with_partial_relro: $(SRC)
	gcc $< -o $@ $(GCCFLAGS) $(NO_CANARY) $(NO_NX) $(PARTIAL_RELRO) $(NO_PIE)

$(BIN)/with_rpath: $(SRC)
	gcc $< -o $@ $(GCCFLAGS) $(NO_CANARY) $(NO_NX) $(NO_RELRO) $(NO_PIE) $(RPATH)

$(BIN)/with_runpath: $(SRC)
	gcc $< -o $@ $(GCCFLAGS) $(NO_CANARY) $(NO_NX) $(NO_RELRO) $(NO_PIE) $(RUNPATH)

$(BIN)/with_safestack: $(SRC)
	clang $< -o $@ $(SAFE_STACK)

$(BIN)/with_cfi: $(SRC)
	clang $< -o $@ $(CFI)

$(BIN)/with_fortify: $(SRC)
	clang $< -o $@ $(FORTIFY)

#$(BIN)/with_selfrando: $(SRC)
#	srenv gcc $< -o $@ $(GCCFLAGS) $(NO_CANARY) $(NO_NX) $(NO_RELRO) $(NO_PIE)

$(BIN)/protected: $(SRC)
	gcc $< -o $@ $(GCCFLAGS) $(CANARY) $(NX) $(RELRO) $(PIE)

verify:
	@/bin/checksec --dir=$(BIN) --extended --output=json

clean:
	rm -rf $(BINS)