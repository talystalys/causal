#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define BUF_SIZE 64
#define SENTINEL 0x5A

int main(int argc, char **argv) {
    if (argc < 2) {
        return 99;
    }

    const char *path = argv[1];
    long fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CREAT, 0600);
    if (fd < 0) {
        return 98;
    }

    unsigned char buf[BUF_SIZE];
    memset(buf, SENTINEL, sizeof(buf));

    long nread = syscall(SYS_read, fd, buf, (size_t)BUF_SIZE);
    syscall(SYS_close, fd);

    
    if (nread != 0) {
        return 42;
    }

    
    for (size_t i = 0; i < BUF_SIZE; i++) {
        if (buf[i] != SENTINEL) {
            return 42;
        }
    }

    return 0;
}
