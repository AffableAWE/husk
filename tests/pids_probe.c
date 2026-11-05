#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
    int n = argc > 1 ? atoi(argv[1]) : 20;
    int ok = 0, failed = 0;

    for (int i = 0; i < n; i++) {
        pid_t p = fork();
        if (p == 0) {
            sleep(10);
            _exit(0);
        }
        if (p < 0)
            failed++;
        else
            ok++;
    }
    printf("forked=%d failed=%d errno=%d\n", ok, failed, failed ? errno : 0);
    fflush(stdout);
    sleep(10);
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
    return 0;
}
