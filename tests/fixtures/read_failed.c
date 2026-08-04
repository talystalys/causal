#define _GNU_SOURCE
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    char buf[64];
    // Explicit invalid fd = -1
    long ret = syscall(SYS_read, -1, buf, (size_t)sizeof(buf));

    // syscall() wrapper returns -1 on error and sets errno
    if (ret == -1 && errno == EBADF) {
        return 0;
    }

    return 42;
}
