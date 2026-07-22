#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    const char msg[] = "hello\n";
    long rc = syscall(SYS_write, STDOUT_FILENO, msg, 6);
    return rc == 6 ? 0 : 1;
}
