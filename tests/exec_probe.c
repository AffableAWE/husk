/* Test helper: a tiny statically linked executable used to exercise command
 * resolution (absolute symlinks and PATH search) without depending on a shell
 * or shared libraries inside the rootfs. */
#include <stdio.h>

int main(void)
{
    puts("exec-probe-ok");
    return 0;
}
