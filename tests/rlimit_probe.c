#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

int main(void)
{
    struct rlimit nofile, fsize;
    int fds[1024];
    int n = 0;
    int fd;

    if (getrlimit(RLIMIT_NOFILE, &nofile) < 0)
        return 2;
    if (getrlimit(RLIMIT_FSIZE, &fsize) < 0)
        return 2;
    printf("nofile_soft=%llu nofile_hard=%llu fsize_soft=%llu fsize_hard=%llu\n",
           (unsigned long long)nofile.rlim_cur,
           (unsigned long long)nofile.rlim_max,
           (unsigned long long)fsize.rlim_cur,
           (unsigned long long)fsize.rlim_max);

    for (;;) {
        fd = open("/etc/passwd", O_RDONLY);
        if (fd < 0)
            break;
        if (n < (int)(sizeof(fds) / sizeof(fds[0])))
            fds[n] = fd;
        n++;
    }
    printf("open_count=%d open_errno=%d\n", n, errno);
    for (int i = 0; i < n && i < (int)(sizeof(fds) / sizeof(fds[0])); i++)
        close(fds[i]);

    signal(SIGXFSZ, SIG_IGN);
    fd = open("/tmp/fsize-probe", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("fsize_open_failed errno=%d\n", errno);
        return 3;
    }
    errno = 0;
    {
        char buf[8192];
        ssize_t w;
        memset(buf, 'x', sizeof(buf));
        w = write(fd, buf, sizeof(buf));
        printf("fsize_write_rc=%zd errno=%d\n", w, errno);
    }
    close(fd);
    return 0;
}
