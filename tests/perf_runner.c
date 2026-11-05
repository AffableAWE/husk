#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long long ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
    long iterations;
    char **husk_argv;
    int i;

    if (argc < 4) {
        fprintf(stderr, "usage: %s N HUSK ARGS...\n", argv[0]);
        return 2;
    }
    iterations = strtol(argv[1], NULL, 10);
    if (iterations <= 0)
        return 2;
    husk_argv = &argv[2];

    printf("iteration,rc,startup_ns,full_ns,clone_ns,cgroup_ns,network_ns,ready_ns,done_ns\n");
    for (i = 0; i < iterations; i++) {
        char path[] = "/tmp/husk-perf-XXXXXX";
        long long start;
        long long phase[5] = {-1, -1, -1, -1, -1};
        int fd = mkstemp(path);
        pid_t pid;
        int status = 0;
        FILE *f;

        if (fd < 0) {
            perror("mkstemp");
            return 3;
        }
        close(fd);
        setenv("HUSK_PERF_FILE", path, 1);
        start = ns();
        pid = fork();
        if (pid == 0) {
            execv(husk_argv[0], husk_argv);
            _exit(127);
        }
        if (pid < 0) {
            perror("fork");
            unlink(path);
            return 3;
        }
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
            ;
        f = fopen(path, "r");
        if (f != NULL) {
            int p;
            long long t;
            while (fscanf(f, "%d %lld", &p, &t) == 2) {
                if (p >= 0 && p < 5)
                    phase[p] = t;
            }
            fclose(f);
        }
        unlink(path);
        printf("%d,%d,%lld,%lld,%lld,%lld,%lld,%lld,%lld\n", i,
               WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status),
               phase[3] >= 0 ? phase[3] - start : -1,
               phase[4] >= 0 ? phase[4] - start : -1,
               phase[0] >= 0 ? phase[0] - start : -1,
               phase[1] >= 0 ? phase[1] - start : -1,
               phase[2] >= 0 ? phase[2] - start : -1,
               phase[3] >= 0 ? phase[3] - start : -1,
               phase[4] >= 0 ? phase[4] - start : -1);
        fflush(stdout);
    }
    return 0;
}
