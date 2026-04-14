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
	echo '{ corrupt json "system": "syftsys","name": "libhello_world.so","version": "0.01","pure:0.01"}' | objcopy --add-section .note.package=/dev/stdin --set-section-flags .note.package=noload,readonly $@

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
	echo '{corrupt json ..._syfttestfixture:0.01"}' | objcopy --add-section .note.package=/dev/stdin --set-section-flags .note.package=noload,readonly $@

testfixture: $(BIN_DIR)/$(EXECUTABLE)

clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR) $(BIN_DIR) $(EXECUTABLE)

.PHONY: all clean 

