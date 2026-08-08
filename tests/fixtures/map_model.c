#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

int main(void) {
    // 1. Allocate 64KB (16 pages) RW private anonymous mapping
    size_t total_size = 65536;
    void *addr = (void *)syscall(SYS_mmap, NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    uint8_t *ptr = (uint8_t *)addr;
    ptr[0] = 0xAA;
    ptr[16384] = 0xBB;
    ptr[32768] = 0xCC;
    ptr[49152] = 0xDD;

    // 2. Change protection of middle subrange [16KB..32KB] to RX
    long prot_res = syscall(SYS_mprotect, ptr + 16384, 16384, PROT_READ | PROT_EXEC);
    if (prot_res != 0) {
        perror("mprotect failed");
        return 2;
    }

    // 3. Unmap subrange [32KB..48KB]
    long unmap_res = syscall(SYS_munmap, ptr + 32768, 16384);
    if (unmap_res != 0) {
        perror("munmap subrange failed");
        return 3;
    }

    // 4. Unmap remainder [0..32KB] and [48KB..64KB]
    long unmap_res1 = syscall(SYS_munmap, ptr, 32768);
    long unmap_res2 = syscall(SYS_munmap, ptr + 49152, 16384);
    if (unmap_res1 != 0 || unmap_res2 != 0) {
        perror("munmap remainder failed");
        return 4;
    }

    return 0;
}
