CC = g++
CFLAGS = -std=c++17 -Wall -Wextra -pedantic
BUILD_DIR := ./build
BIN_DIR := ./bin
LIB_DIR := $(BIN_DIR)/lib



all: testfixtures

testfixtures: 
	$(MAKE) -C elfsrc
	
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

.PHONY: all clean testfixtures

