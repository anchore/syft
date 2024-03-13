LDFLAGS := -L/lib64 -lstdc++

SRC_DIR := ./
BUILD_DIR := ../build
BIN_DIR := ../bin
LIB_DIR := $(BIN_DIR)/lib

LIB_NAME := hello_world
LIB_SRC := $(SRC_DIR)/hello_world.cpp
LIB_OBJ := $(BUILD_DIR)/$(LIB_NAME).o
LIB_SO := $(LIB_DIR)/lib$(LIB_NAME).so

EXECUTABLE := elfbinwithnestedlib
EXEC_SRC := $(SRC_DIR)/testbin.cpp
EXEC_OBJ := $(BUILD_DIR)/$(EXECUTABLE).o



all: testfixture

$(LIB_SO): $(LIB_OBJ) | $(LIB_DIR)
	$(CC) -shared -o $@ $<
	echo '{"type": "testfixture","license":"MIT","commit":"5534c38d0ffef9a3f83154f0b7a7fb6ab0ab6dbb","sourceRepo":"https://github.com/someone/somewhere.git","vendor": "syft","system": "syftsys","name": "libhello_world.so","version": "0.01","purl": "pkg:generic/syftsys/syfttestfixture@0.01","cpe": "cpe:/o:syft:syftsys_testfixture_syfttestfixture:0.01"}' | objcopy --add-section .note.package=/dev/stdin --set-section-flags .note.package=noload,readonly $@

$(LIB_OBJ): $(LIB_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(EXEC_OBJ): $(EXEC_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
$(LIB_DIR):
	mkdir -p $(LIB_DIR)

$(BIN_DIR)/$(EXECUTABLE): $(EXEC_OBJ) $(LIB_SO) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -L$(LIB_DIR) -l$(LIB_NAME) $(LDFLAGS)
	echo '{"type": "testfixture","license":"MIT","commit":"5534c38d0ffef9a3f83154f0b7a7fb6ab0ab6dbb","sourceRepo":"https://github.com/someone/somewhere.git","vendor": "syft","system": "syftsys","name": "syfttestfixture","version": "0.01","purl": "pkg:generic/syftsys/syfttestfixture@0.01","cpe": "cpe:/o:syft:syftsys_testfixture_syfttestfixture:0.01"}' | objcopy --add-section .note.package=/dev/stdin --set-section-flags .note.package=noload,readonly $@

testfixture: $(BIN_DIR)/$(EXECUTABLE)

clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR) $(BIN_DIR) $(EXECUTABLE)

.PHONY: all clean 

