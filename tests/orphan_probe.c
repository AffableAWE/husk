/* Test helper: create an orphaned grandchild, then count live PIDs in the
 * container's PID namespace. If husk (PID 1) reaps the orphan, the grandchild
 * does not remain as a zombie and the count is 2 (init + workload). */
#define _GNU_SOURCE

#include <dirent.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int count_pids(void)
{
    DIR *dir = opendir("/proc");
    struct dirent *de;
    int count = 0;

    if (dir == NULL)
        return -1;

    while ((de = readdir(dir)) != NULL) {
        const char *p = de->d_name;

        while (*p >= '0' && *p <= '9')
            p++;
        if (*p == '\0' && de->d_name[0] != '\0')
            count++;
    }
    closedir(dir);
    return count;
}

int main(void)
{
    pid_t mid = fork();

    if (mid < 0)
        return 1;
    if (mid == 0) {
        pid_t grandchild = fork();

        if (grandchild < 0)
            _exit(1);
        if (grandchild == 0) {
            usleep(200000);
            _exit(0);
        }
        _exit(0); /* grandchild is reparented to PID 1 */
    }

    if (waitpid(mid, NULL, 0) < 0)
        return 1;
    usleep(800000); /* give the orphan time to exit and be reaped */

    printf("procs=%d\n", count_pids());
    return 0;
}
