#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// source: https://github.com/trailofbits/clang-cfi-showcase/blob/master/cfi_icall.c

typedef int (*int_arg_fn)(int);
typedef int (*float_arg_fn)(float);

static int int_arg(int arg) {
    printf("In %s: (%d)\n", __FUNCTION__, arg);
    return 0;
}

static int float_arg(float arg) {
    printf("CFI should protect transfer to here\n");
    printf("In %s: (%f)\n", __FUNCTION__, (double)arg);
    return 0;
}

static int bad_int_arg(int arg) {
    printf("CFI will not protect transfer to here\n");
    printf("In %s: (%d)\n", __FUNCTION__, arg);
    return 0;
}

static int not_entry_point(int arg) {
    // nop sled for x86 / x86-64
    // these instructions act as a buffer
    // for an indirect control flow transfer to skip
    // a valid function entry point, but continue
    // to execute normal code
    __asm__ volatile (
            "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
            "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
            "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
            "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
            "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
            "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
            "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
            "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
            );
    printf("CFI ensures control flow only transfers to potentially valid destinations\n");
    printf("In %s: (%d)\n", __FUNCTION__, arg);
    // need to exit or the program will segfault anyway,
    // since the indirect call skipped the function preamble
    exit(arg);
}

struct foo {
    int_arg_fn int_funcs[1];
    int_arg_fn bad_int_funcs[1];
    float_arg_fn float_funcs[1];
    int_arg_fn not_entries[1];
};

// the struct aligns the function pointer arrays
// so indexing past the end will reliably
// call working function pointers
static struct foo f = {
    .int_funcs = {int_arg},
    .bad_int_funcs = {bad_int_arg},
    .float_funcs = {float_arg},
    .not_entries = {(int_arg_fn)((uintptr_t)(not_entry_point)+0x20)}
};

void simple1() {
    char buf[16];
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
}

void simple2() {
    char buf[16];
    scanf("%s", buf);
}


int main(int argc, char **argv) {
    if(argc != 2) {
        printf("Usage: %s <option>\n", argv[0]);
        printf("Option values:\n");
        printf("\t0\tCall correct function\n");
        printf("\t1\tCall the wrong function but with the same signature\n");
        printf("\t2\tCall a float function with an int function signature\n");
        printf("\t3\tCall into the middle of a function\n");
        printf("\n");
        printf("\tAll other options are undefined, but should be caught by CFI :)\n");
        printf("\n\n");
        printf("Here are some pointers so clang doesn't optimize away members of `struct foo f`:\n");
        printf("\tint_funcs: %p\n", (void*)f.int_funcs);
        printf("\tbad_int_funcs: %p\n", (void*)f.bad_int_funcs);
        printf("\tfloat_funcs: %p\n", (void*)f.float_funcs);
        printf("\tnot_entries: %p\n", (void*)f.not_entries);
        return 1;
    }

    simple1();
    simple2();

    printf("Calling a function:\n");

    int idx = argv[1][0] - '0';

    return f.int_funcs[idx](idx);
}