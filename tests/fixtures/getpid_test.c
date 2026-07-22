#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    pid_t pid = (pid_t)syscall(SYS_getpid);
    return pid > 0 ? 0 : 1;
}
