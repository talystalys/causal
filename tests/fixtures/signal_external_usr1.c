#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_received = 0;
static volatile sig_atomic_t g_sig = 0;
static volatile sig_atomic_t g_code = 0;
static volatile sig_atomic_t g_sender_pid = 0;

static void handler(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;
    g_received = 1;
    g_sig = sig;
    if (info) {
        g_code = info->si_code;
        g_sender_pid = info->si_pid;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ready-file-path>\n", argv[0]);
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        perror("sigaction");
        return 2;
    }

    // Write our PID to the readiness file
    FILE *f = fopen(argv[1], "w");
    if (!f) {
        perror("fopen ready-file");
        return 3;
    }
    fprintf(f, "%d\n", (int)getpid());
    fflush(f);
    fclose(f);

    // Busy loop without syscalls until signal arrives
    while (!g_received) {
        // Pure userspace spin
    }

    // Validate received signal metadata
    if (g_sig != SIGUSR1) {
        fprintf(stderr, "signal mismatch: expected %d, got %d\n", SIGUSR1, (int)g_sig);
        return 4;
    }

    const char *expect_code_env = getenv("CAUSAL_EXPECT_SIGNAL_CODE");
    if (expect_code_env) {
        int expected_code = atoi(expect_code_env);
        if ((int)g_code != expected_code) {
            fprintf(stderr, "si_code mismatch: expected %d, got %d\n", expected_code, (int)g_code);
            return 5;
        }
    }

    const char *expect_pid_env = getenv("CAUSAL_EXPECT_SIGNAL_SENDER_PID");
    if (expect_pid_env) {
        int expected_sender = atoi(expect_pid_env);
        if ((int)g_sender_pid != expected_sender) {
            fprintf(stderr, "si_pid mismatch: expected %d, got %d\n", expected_sender, (int)g_sender_pid);
            return 6;
        }
    }

    return 0;
}
