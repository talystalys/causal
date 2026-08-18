#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t g_received = 0;

static void handler(int sig) {
    (void)sig;
    g_received = 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        return 2;
    }

    int fds[2];
    if (pipe(fds) != 0) {
        return 3;
    }

    
    int rfd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (rfd < 0) {
        return 4;
    }
    dprintf(rfd, "%d\n", (int)getpid());
    close(rfd);

    
    char buf[16];
    long nread = syscall(SYS_read, fds[0], buf, sizeof(buf));
    (void)nread;

    close(fds[0]);
    close(fds[1]);

    return 0;
}
