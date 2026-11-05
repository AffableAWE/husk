/* Test launcher: set SIGCHLD to SIG_IGN and exec husk.
 *
 * This checks that husk explicitly installs SIGCHLD=SIG_DFL in itself and in
 * the PID-namespace init instead of inheriting an auto-reaping disposition that
 * existed in the launcher. The disposition of SIG_IGN survives execve(2);
 * SA_NOCLDWAIT is a sigaction flag on a handler and is not claimed here.
 *
 * Usage: sigchld-launcher /path/to/husk run --rootfs DIR -- COMMAND ...
 */
#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("sigchld-launcher: sigaction(SIGCHLD, SIG_IGN)");
        return 111;
    }

    if (argc < 2) {
        fprintf(stderr, "usage: %s PROGRAM [ARG...]\n", argv[0]);
        return 2;
    }

    execv(argv[1], &argv[1]);
    perror("sigchld-launcher: execv");
    return 111;
}
