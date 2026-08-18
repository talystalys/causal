#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    
    raise(SIGSTOP);
    return 0;
}
