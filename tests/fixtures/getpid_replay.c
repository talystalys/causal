#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    long observed = syscall(SYS_getpid);
    if (observed <= 0) {
        return 99; 
    }

    const char *expected_env = getenv("CAUSAL_EXPECT_GETPID");
    if (expected_env == NULL) {
        return 0; 
    }

    char *endptr = NULL;
    errno = 0;
    long expected_val = strtol(expected_env, &endptr, 10);

    if (errno != 0 || endptr == expected_env || *endptr != '\0' || expected_val <= 0 || expected_val > INT_MAX) {
        return 98; 
    }

    if (observed == expected_val) {
        return 0; 
    }

    return 42; 
}
