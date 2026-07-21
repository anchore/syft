CC = g++
CFLAGS = -std=c++17 -Wall -Wextra -pedantic
BUILD_DIR := ./build
LIB_DIR := ./lib
BIN_DIR := ./bin


all: testfixtures

testfixtures: 
	$(MAKE) -C elfsrc1
	$(MAKE) -C elfsrc2

clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR) $(BIN_DIR)

.PHONY: all clean testfixtures

