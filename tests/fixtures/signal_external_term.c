#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ready-file-path>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "w");
    if (!f) {
        perror("fopen ready-file");
        return 2;
    }
    fprintf(f, "%d\n", (int)getpid());
    fflush(f);
    fclose(f);

    // Busy loop indefinitely until terminated by default action of external signal
    while (1) {
        // Pure userspace spin
    }

    return 0;
}
