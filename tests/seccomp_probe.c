#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

int main(void)
{
    long rc;
    int fd;
    char buf[8];
    ssize_t n;

    rc = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    printf("ptrace_rc=%ld ptrace_errno=%d(%s)\n", rc, errno,
           strerror(errno));

    fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        printf("ordinary_open_failed errno=%d\n", errno);
        return 2;
    }
    n = read(fd, buf, sizeof(buf));
    close(fd);
    printf("ordinary_open_ok read=%zd pid=%ld\n", n, (long)getpid());
    return 0;
}
