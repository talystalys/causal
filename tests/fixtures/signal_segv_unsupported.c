#define _GNU_SOURCE
#include <stdio.h>

int main(void) {
    
    volatile int *ptr = (volatile int *)0;
    *ptr = 42;
    return 0;
}
