#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void dump_status(const char *path, const char *label)
{
    char buf[8192];
    int fd = open(path, O_RDONLY);
    ssize_t n;

    printf("--%s--\n", label);
    if (fd < 0) {
        printf("open_failed=%d\n", errno);
        return;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return;
    buf[n] = '\0';
    {
        char *line = strtok(buf, "\n");
        while (line != NULL) {
            if (strncmp(line, "Cap", 3) == 0 ||
                strncmp(line, "NoNewPrivs:", 11) == 0 ||
                strncmp(line, "Seccomp:", 8) == 0 ||
                strncmp(line, "Uid:", 4) == 0 ||
                strncmp(line, "Gid:", 4) == 0)
                printf("%s\n", line);
            line = strtok(NULL, "\n");
        }
    }
}

int main(void)
{
    char buf[4096];
    int fd = open("/proc/self/cgroup", O_RDONLY);
    ssize_t n;

    dump_status("/proc/self/status", "self");
    dump_status("/proc/1/status", "init");
    printf("--cgroup--\n");
    if (fd >= 0) {
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            printf("%s", buf);
        }
    }
    printf("--cgroup_mount--\n");
    printf("sys_fs_cgroup=%s\n",
           access("/sys/fs/cgroup", F_OK) == 0 ? "present" : "absent");
    fd = open("/proc/self/mountinfo", O_RDONLY);
    if (fd >= 0) {
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            printf("cgroup2_mount=%s\n",
                   strstr(buf, " cgroup2 ") != NULL ? "present" : "absent");
        }
    }
    return 0;
}
