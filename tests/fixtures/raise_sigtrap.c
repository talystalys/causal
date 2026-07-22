#include <signal.h>

int main(void) {
    raise(SIGTRAP);
    return 99;
}
