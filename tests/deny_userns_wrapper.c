/* Test-only wrapper: deny clone(CLONE_NEWUSER) with seccomp, then exec husk.
 *
 * This exercises the runtime's denied-namespace-creation path without changing
 * any host-wide setting. The seccomp filter is installed only in this test
 * process and is inherited by the exec'd husk process; the runtime itself does
 * not use seccomp.
 *
 * Usage: deny_userns_wrapper PROGRAM [ARG...]
 */
#define _GNU_SOURCE

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__aarch64__)
#define HUSK_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define HUSK_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#error "deny_userns_wrapper needs an aarch64 or x86_64 audit arch"
#endif

int main(int argc, char **argv)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, HUSK_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEWUSER, 0, 1),
        BPF_STMT(BPF_RET | BPF_K,
                 SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (argc < 2) {
        fprintf(stderr, "usage: %s PROGRAM [ARG...]\n", argv[0]);
        return 2;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("deny_userns_wrapper: PR_SET_NO_NEW_PRIVS");
        return 111;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("deny_userns_wrapper: PR_SET_SECCOMP");
        return 111;
    }
    execv(argv[1], &argv[1]);
    perror("deny_userns_wrapper: execv");
    return 111;
}
