#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_usr1_received = 0;
static volatile sig_atomic_t g_usr2_received = 0;

static void handler_usr1(int sig, siginfo_t *info, void *ucontext) {
    (void)info;
    (void)ucontext;
    if (sig == SIGUSR1) {
        g_usr1_received = 1;
    }
}

static void handler_usr2(int sig, siginfo_t *info, void *ucontext) {
    (void)info;
    (void)ucontext;
    if (sig == SIGUSR2) {
        g_usr2_received = 1;
    }
}

int main(void) {
    struct sigaction sa1;
    memset(&sa1, 0, sizeof(sa1));
    sa1.sa_sigaction = handler_usr1;
    sa1.sa_flags = SA_SIGINFO;
    sigemptyset(&sa1.sa_mask);
    if (sigaction(SIGUSR1, &sa1, NULL) != 0) {
        return 1;
    }

    struct sigaction sa2;
    memset(&sa2, 0, sizeof(sa2));
    sa2.sa_sigaction = handler_usr2;
    sa2.sa_flags = SA_SIGINFO;
    sigemptyset(&sa2.sa_mask);
    if (sigaction(SIGUSR2, &sa2, NULL) != 0) {
        return 2;
    }

    
    raise(SIGUSR1);
    if (!g_usr1_received) {
        return 3;
    }

    
    pid_t pid = getpid();
    if (pid <= 0) {
        return 4;
    }

    
    raise(SIGUSR2);
    if (!g_usr2_received) {
        return 5;
    }

    return 0;
}
