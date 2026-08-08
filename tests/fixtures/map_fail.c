#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

int main(void) {
    // 1. Deliberately trigger failed mmap (len = 0 returns EINVAL / MAP_FAILED)
    long mmap_res = syscall(SYS_mmap, NULL, 0, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mmap_res != -1) {
        fprintf(stderr, "unexpected mmap success with len=0: %ld\n", mmap_res);
        return 1;
    }

    // 2. Deliberately trigger failed munmap (unaligned address returns EINVAL)
    long munmap_res = syscall(SYS_munmap, (void *)0x123, 4096);
    if (munmap_res != -1) {
        fprintf(stderr, "unexpected munmap success with unaligned addr: %ld\n", munmap_res);
        return 2;
    }

    // 3. Deliberately trigger failed mprotect (unaligned address returns EINVAL)
    long mprot_res = syscall(SYS_mprotect, (void *)0x456, 4096, PROT_READ);
    if (mprot_res != -1) {
        fprintf(stderr, "unexpected mprotect success with unaligned addr: %ld\n", mprot_res);
        return 3;
    }

    return 0;
}
