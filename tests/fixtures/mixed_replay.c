#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define EXPECTED_PAYLOAD "CAUSAL_M4_PAYLOAD_21B"
#define EXPECTED_LEN 21
#define BUF_SIZE 64
#define SENTINEL 0xA5

int main(int argc, char **argv) {
    if (argc < 2) {
        return 99;
    }

    // 1. SYS_getpid check
    long pid = syscall(SYS_getpid);
    const char *expected_env = getenv("CAUSAL_EXPECT_GETPID");
    if (expected_env != NULL && *expected_env != '\0') {
        long expected_pid = atol(expected_env);
        if (pid != expected_pid) {
            return 42;
        }
    }

    // 2. SYS_read check
    const char *path = argv[1];
    long fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CREAT, 0600);
    if (fd < 0) {
        return 98;
    }

    unsigned char buf[BUF_SIZE];
    memset(buf, SENTINEL, sizeof(buf));

    long nread = syscall(SYS_read, fd, buf, (size_t)BUF_SIZE);
    syscall(SYS_close, fd);

    if (nread != EXPECTED_LEN) {
        return 42;
    }

    if (memcmp(buf, EXPECTED_PAYLOAD, EXPECTED_LEN) != 0) {
        return 42;
    }

    for (size_t i = EXPECTED_LEN; i < BUF_SIZE; i++) {
        if (buf[i] != SENTINEL) {
            return 42;
        }
    }

    return 0;
}
