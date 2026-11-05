#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    double seconds = argc > 1 ? atof(argv[1]) : 5.0;
    double end;
    volatile unsigned long x = 0;

    printf("cpu-probe-start\n");
    fflush(stdout);
    end = now() + seconds;
    while (now() < end)
        for (unsigned long i = 0; i < 100000; i++)
            x += i;
    printf("cpu-probe-done x=%lu\n", x);
    return 0;
}
