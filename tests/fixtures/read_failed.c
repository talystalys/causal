#define _GNU_SOURCE
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    char buf[64];
    
    long ret = syscall(SYS_read, -1, buf, (size_t)sizeof(buf));

    
    if (ret == -1 && errno == EBADF) {
        return 0;
    }

    return 42;
}
