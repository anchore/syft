package main

/*
#include <string.h>
#include <stdio.h>

int get_length(const char* s) {
    return strlen(s);
}
*/
import "C"
import "fmt"

func main() {
	msg := C.CString("Hello from CGO!")
	length := C.get_length(msg)
	fmt.Printf("String length: %d\n", int(length))
}
