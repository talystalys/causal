#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    // Deliberately raise unsupported stopping signal
    raise(SIGSTOP);
    return 0;
}
