#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
    // 1. Query initial brk
    long initial_brk = syscall(SYS_brk, 0);
    if (initial_brk < 0) {
        perror("initial SYS_brk failed");
        return 1;
    }

    // 2. Grow heap by 64KB (must be page-aligned)
    long grown_brk = syscall(SYS_brk, initial_brk + 65536);
    if (grown_brk <= initial_brk) {
        perror("growth SYS_brk failed");
        return 2;
    }

    // 3. Shrink heap back to initial brk
    long shrunk_brk = syscall(SYS_brk, initial_brk);
    if (shrunk_brk < 0) {
        perror("shrink SYS_brk failed");
        return 3;
    }

    return 0;
}
