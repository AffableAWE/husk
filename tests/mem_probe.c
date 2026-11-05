#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    size_t mb = argc > 1 ? (size_t)strtoull(argv[1], NULL, 10) : 8;
    unsigned int sleep_s = argc > 2 ? (unsigned int)strtoul(argv[2], NULL, 10) : 10;
    size_t bytes = mb * 1024 * 1024;
    volatile unsigned char *p;

    p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        printf("mmap-failed errno=%d\n", errno);
        return 2;
    }
    for (size_t i = 0; i < bytes; i += 4096)
        p[i] = (unsigned char)i;
    printf("allocated=%zu sleeping=%u\n", bytes, sleep_s);
    fflush(stdout);
    sleep(sleep_s);
    printf("done\n");
    return 0;
}
