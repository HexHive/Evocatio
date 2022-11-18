#include "sanitizer/asan_interface.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

/*
 * This is our custom implemantation of `__asan_on_error`.
 * This is called by ASan before crashing. Inside it we
 * have access to all fuctions defined in this header file:
 *
 * https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/sanitizer/asan_interface.h
 */

void __my_asan_on_error() {
	printf("INFO: Hello from `__asan_on_error`!\n");
}
