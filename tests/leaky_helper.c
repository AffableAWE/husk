/* Test-only deliberate leak.
 *
 * Usage: leaky_helper
 *
 * Forks a child that stays alive until it is killed, prints the child PID to
 * stdout, and exits 0. The child deliberately keeps the parent's process
 * group, so a supervisor that owns that group can observe it, then kill and
 * reap it.
 *
 * This helper is used only by the harness negative control. It never invokes
 * husk: the leak is manufactured on the test side so the pre-cleanup
 * assertion can be shown to fail before emergency cleanup removes the
 * descendant.
 *
 * Do not install this in a runtime rootfs or use it as a service helper.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    pid_t child;

    child = fork();
    if (child < 0) {
        perror("leaky_helper: fork");
        return 111;
    }
    if (child == 0) {
        /* Do not hold the caller's stdio open after the parent exits. */
        (void)close(STDIN_FILENO);
        (void)close(STDOUT_FILENO);
        (void)close(STDERR_FILENO);
        for (;;)
            (void)pause();
    }

    if (printf("%ld\n", (long)child) < 0 || fflush(stdout) != 0) {
        perror("leaky_helper: write child pid");
        (void)kill(child, SIGKILL);
        return 111;
    }
    return 0;
}
