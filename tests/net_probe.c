#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int fd;
    struct sockaddr_in sa;
    int one = 1;

    if (argc < 3) {
        fprintf(stderr, "usage: net_probe server PORT | client IP PORT\n");
        return 2;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 3;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)atoi(
        strcmp(argv[1], "client") == 0 && argc > 3 ? argv[3] : argv[2]));
    if (strcmp(argv[1], "server") == 0) {
        char buf[16];
        int c;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
            return 4;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("bind");
            return 5;
        }
        if (listen(fd, 1) < 0) {
            perror("listen");
            return 6;
        }
        printf("listening\n");
        fflush(stdout);
        c = accept(fd, NULL, NULL);
        if (c < 0) {
            perror("accept");
            return 7;
        }
        if (read(c, buf, sizeof(buf) - 1) <= 0) {
            perror("read");
            close(c);
            return 8;
        }
        if (write(c, "ok", 2) < 0) { /* best effort */ }
        close(c);
        printf("server-ok\n");
        close(fd);
        return 0;
    }
    if (strcmp(argv[1], "client") == 0) {
        char buf[16];
        ssize_t n;
        if (inet_pton(AF_INET, argv[2], &sa.sin_addr) != 1) {
            fprintf(stderr, "bad ip\n");
            return 9;
        }
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("connect");
            return 10;
        }
        n = write(fd, "ping", 4);
        if (n < 0) {
            perror("write");
            close(fd);
            return 11;
        }
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n < 0) {
            perror("read");
            return 12;
        }
        buf[n] = '\0';
        printf("reply=%s\n", buf);
        return 0;
    }
    fprintf(stderr, "unknown mode\n");
    return 13;
}
