/* Resource limits and security restrictions.
 *
 * Policy "husk-minimal-v1":
 *   - init after setup: effective/permitted/inheritable/bounding = CAP_KILL
 *     plus temporary CAP_SETPCAP so the workload child can drop its own
 *     bounding set; CAP_SETPCAP is removed from init after the workload exec
 *     handshake. Ambient is empty. Securebits are NOROOT|NOROOT_LOCKED and
 *     NO_SETUID_FIXUP|NO_SETUID_FIXUP_LOCKED.
 *   - workload: all five capability sets empty, no_new_privs=1.
 *   - both: an architecture-checked seccomp filter denies namespace/mount/
 *     tracing/module/BPF style operations; ordinary file, process, and socket
 *     syscalls remain allowed.
 *   - workload rlimits are applied by init before fork and verified.
 */
#define _GNU_SOURCE

#include "husk.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/securebits.h>
#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS SECCOMP_RET_KILL
#endif
#ifndef CAP_LAST_CAP
#define CAP_LAST_CAP 40
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#if defined(__aarch64__)
#define HUSK_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define HUSK_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#error "husk seccomp policy needs an aarch64 or x86_64 audit arch"
#endif

#define HUSK_CAP_BIT(cap) (1ULL << (cap))
#define HUSK_INIT_TEMP_CAPS \
    (HUSK_CAP_BIT(CAP_KILL) | HUSK_CAP_BIT(CAP_SETPCAP))
#define HUSK_INIT_FINAL_CAPS HUSK_CAP_BIT(CAP_KILL)

static void set_err(char *err, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;

    if (err == NULL || errlen == 0)
        return;
    va_start(ap, fmt);
    (void)vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static int set_caps(uint64_t mask)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];

    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    data[0].effective = (uint32_t)mask;
    data[0].permitted = (uint32_t)mask;
    data[0].inheritable = (uint32_t)mask;
    data[1].effective = (uint32_t)(mask >> 32);
    data[1].permitted = (uint32_t)(mask >> 32);
    data[1].inheritable = (uint32_t)(mask >> 32);
    return (int)syscall(SYS_capset, &hdr, data);
}

static int get_caps(uint64_t *mask)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];

    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (syscall(SYS_capget, &hdr, data) < 0)
        return -1;
    *mask = ((uint64_t)data[1].effective << 32) | data[0].effective;
    {
        uint64_t perm =
            ((uint64_t)data[1].permitted << 32) | data[0].permitted;
        uint64_t inh =
            ((uint64_t)data[1].inheritable << 32) | data[0].inheritable;

        if (perm != *mask || inh != *mask)
            return -1;
    }
    return 0;
}

static int clear_ambient(char *err, size_t errlen)
{
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
        set_err(err, errlen, "clear ambient capabilities: %s",
                strerror(errno));
        return -1;
    }
    return 0;
}

static int drop_bounding_except(uint64_t keep, char *err, size_t errlen)
{
    int cap;

    for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
        if (keep & HUSK_CAP_BIT(cap))
            continue;
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 && errno != EINVAL) {
            set_err(err, errlen, "drop bounding capability %d: %s", cap,
                    strerror(errno));
            return -1;
        }
    }
    return 0;
}

static int set_securebits(char *err, size_t errlen)
{
    unsigned long bits = SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
                         SECBIT_NO_SETUID_FIXUP |
                         SECBIT_NO_SETUID_FIXUP_LOCKED;

    if (prctl(PR_SET_SECUREBITS, bits, 0, 0, 0) < 0) {
        set_err(err, errlen, "set securebits: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int set_no_new_privs(char *err, size_t errlen)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        set_err(err, errlen, "set no_new_privs: %s", strerror(errno));
        return -1;
    }
    return 0;
}

struct filter_builder {
    struct sock_filter insn[256];
    size_t n;
};

static void emit(struct filter_builder *fb, struct sock_filter insn)
{
    if (fb->n < sizeof(fb->insn) / sizeof(fb->insn[0]))
        fb->insn[fb->n++] = insn;
}

static void emit_deny(struct filter_builder *fb, int nr)
{
    emit(fb, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
    emit(fb, (struct sock_filter)BPF_STMT(
                 BPF_RET | BPF_K,
                 SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)));
}

static void emit_errno(struct filter_builder *fb, int nr, int error)
{
    emit(fb, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
    emit(fb, (struct sock_filter)BPF_STMT(
                 BPF_RET | BPF_K,
                 SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA)));
}

static int install_seccomp(char *err, size_t errlen)
{
    struct filter_builder fb;
    struct sock_fprog prog;
#ifdef __NR_clone
    unsigned int clone_ns_mask =
        CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC |
        CLONE_NEWNET | CLONE_NEWUSER | CLONE_NEWCGROUP;
#ifdef CLONE_NEWTIME
    clone_ns_mask |= CLONE_NEWTIME;
#endif
#endif
    memset(&fb, 0, sizeof(fb));
    prog.filter = fb.insn;
    prog.len = 0;

    emit(&fb, (struct sock_filter)BPF_STMT(
                  BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, arch)));
    emit(&fb, (struct sock_filter)BPF_JUMP(
                  BPF_JMP | BPF_JEQ | BPF_K, HUSK_AUDIT_ARCH, 1, 0));
    emit(&fb, (struct sock_filter)BPF_STMT(
                  BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    emit(&fb, (struct sock_filter)BPF_STMT(
                  BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, nr)));

#if defined(__x86_64__)
    /* The x32 ABI shares AUDIT_ARCH_X86_64 but sets bit 30 in syscall
     * numbers. Reject those numbers explicitly instead of letting an x32
     * syscall pass as an unrelated 64-bit number. */
#define HUSK_X32_SYSCALL_BIT 0x40000000U
    emit(&fb, (struct sock_filter)BPF_JUMP(
                  BPF_JMP | BPF_JSET | BPF_K, HUSK_X32_SYSCALL_BIT, 0, 1));
    emit(&fb, (struct sock_filter)BPF_STMT(
                  BPF_RET | BPF_K,
                  SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)));
#endif

#ifdef __NR_clone3
    /* ENOSYS, not EPERM: libc pthread_create falls back to clone(2) on
     * ENOSYS. clone(2) is still filtered below for namespace flags, so
     * ordinary threads work without granting namespace creation. */
    emit_errno(&fb, __NR_clone3, ENOSYS);
#endif

    /* Deny dangerous host/kernel operations. Ordinary filesystem, process,
     * signal, network, and runtime syscalls are allowed. */
#ifdef __NR_mount
    emit_deny(&fb, __NR_mount);
#endif
#ifdef __NR_umount2
    emit_deny(&fb, __NR_umount2);
#endif
#ifdef __NR_pivot_root
    emit_deny(&fb, __NR_pivot_root);
#endif
#ifdef __NR_chroot
    emit_deny(&fb, __NR_chroot);
#endif
#ifdef __NR_unshare
    emit_deny(&fb, __NR_unshare);
#endif
#ifdef __NR_setns
    emit_deny(&fb, __NR_setns);
#endif
#ifdef __NR_ptrace
    emit_deny(&fb, __NR_ptrace);
#endif
#ifdef __NR_bpf
    emit_deny(&fb, __NR_bpf);
#endif
#ifdef __NR_kexec_load
    emit_deny(&fb, __NR_kexec_load);
#endif
#ifdef __NR_kexec_file_load
    emit_deny(&fb, __NR_kexec_file_load);
#endif
#ifdef __NR_init_module
    emit_deny(&fb, __NR_init_module);
#endif
#ifdef __NR_finit_module
    emit_deny(&fb, __NR_finit_module);
#endif
#ifdef __NR_delete_module
    emit_deny(&fb, __NR_delete_module);
#endif
#ifdef __NR_open_by_handle_at
    emit_deny(&fb, __NR_open_by_handle_at);
#endif
#ifdef __NR_name_to_handle_at
    emit_deny(&fb, __NR_name_to_handle_at);
#endif
#ifdef __NR_perf_event_open
    emit_deny(&fb, __NR_perf_event_open);
#endif
#ifdef __NR_userfaultfd
    emit_deny(&fb, __NR_userfaultfd);
#endif
#ifdef __NR_keyctl
    emit_deny(&fb, __NR_keyctl);
#endif
#ifdef __NR_add_key
    emit_deny(&fb, __NR_add_key);
#endif
#ifdef __NR_request_key
    emit_deny(&fb, __NR_request_key);
#endif
#ifdef __NR_acct
    emit_deny(&fb, __NR_acct);
#endif
#ifdef __NR_quotactl
    emit_deny(&fb, __NR_quotactl);
#endif
#ifdef __NR_quotactl_fd
    emit_deny(&fb, __NR_quotactl_fd);
#endif
#ifdef __NR_swapon
    emit_deny(&fb, __NR_swapon);
#endif
#ifdef __NR_swapoff
    emit_deny(&fb, __NR_swapoff);
#endif
#ifdef __NR_reboot
    emit_deny(&fb, __NR_reboot);
#endif
#ifdef __NR_sethostname
    emit_deny(&fb, __NR_sethostname);
#endif
#ifdef __NR_setdomainname
    emit_deny(&fb, __NR_setdomainname);
#endif
#ifdef __NR_iopl
    emit_deny(&fb, __NR_iopl);
#endif
#ifdef __NR_ioperm
    emit_deny(&fb, __NR_ioperm);
#endif
#ifdef __NR_nfsservctl
    emit_deny(&fb, __NR_nfsservctl);
#endif
#ifdef __NR_vm86
    emit_deny(&fb, __NR_vm86);
#endif
#ifdef __NR_pidfd_getfd
    emit_deny(&fb, __NR_pidfd_getfd);
#endif
#ifdef __NR_process_vm_readv
    emit_deny(&fb, __NR_process_vm_readv);
#endif
#ifdef __NR_process_vm_writev
    emit_deny(&fb, __NR_process_vm_writev);
#endif
#ifdef __NR_mount_setattr
    emit_deny(&fb, __NR_mount_setattr);
#endif
#ifdef __NR_move_mount
    emit_deny(&fb, __NR_move_mount);
#endif
#ifdef __NR_fsopen
    emit_deny(&fb, __NR_fsopen);
#endif
#ifdef __NR_fsconfig
    emit_deny(&fb, __NR_fsconfig);
#endif
#ifdef __NR_fsmount
    emit_deny(&fb, __NR_fsmount);
#endif
#ifdef __NR_fspick
    emit_deny(&fb, __NR_fspick);
#endif
#ifdef __NR_open_tree
    emit_deny(&fb, __NR_open_tree);
#endif
#ifdef __NR_io_uring_setup
    emit_deny(&fb, __NR_io_uring_setup);
#endif
#ifdef __NR_syslog
    emit_deny(&fb, __NR_syslog);
#endif

#ifdef __NR_clone
    /* Allow normal clone/fork; reject namespace-creating flags. */
    emit(&fb, (struct sock_filter)BPF_JUMP(
                  BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3));
    emit(&fb, (struct sock_filter)BPF_STMT(
                  BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[0])));
    emit(&fb, (struct sock_filter)BPF_JUMP(
                  BPF_JMP | BPF_JSET | BPF_K, (int)clone_ns_mask, 0, 1));
    emit(&fb, (struct sock_filter)BPF_STMT(
                  BPF_RET | BPF_K,
                  SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)));
#endif
    emit(&fb, (struct sock_filter)BPF_STMT(
                  BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    if (fb.n >= sizeof(fb.insn) / sizeof(fb.insn[0])) {
        set_err(err, errlen, "seccomp filter is too large");
        return -1;
    }
    prog.len = (unsigned short)fb.n;

    if (set_no_new_privs(err, errlen) < 0)
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) < 0) {
        set_err(err, errlen, "install seccomp filter: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int husk_security_apply_rlimits(const struct husk_config *cfg, char *err,
                                size_t errlen)
{
    struct rlimit rl;

    if (cfg->nofile_set) {
        rl.rlim_cur = (rlim_t)cfg->nofile;
        rl.rlim_max = (rlim_t)cfg->nofile;
        if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
            set_err(err, errlen, "setrlimit(RLIMIT_NOFILE=%llu): %s",
                    cfg->nofile, strerror(errno));
            return -1;
        }
        if (getrlimit(RLIMIT_NOFILE, &rl) < 0 ||
            rl.rlim_cur != (rlim_t)cfg->nofile ||
            rl.rlim_max != (rlim_t)cfg->nofile) {
            set_err(err, errlen,
                    "RLIMIT_NOFILE readback does not match requested %llu",
                    cfg->nofile);
            return -1;
        }
    }
    if (cfg->fsize_set) {
        rl.rlim_cur = (rlim_t)cfg->fsize;
        rl.rlim_max = (rlim_t)cfg->fsize;
        if (setrlimit(RLIMIT_FSIZE, &rl) < 0) {
            set_err(err, errlen, "setrlimit(RLIMIT_FSIZE=%llu): %s",
                    cfg->fsize, strerror(errno));
            return -1;
        }
        if (getrlimit(RLIMIT_FSIZE, &rl) < 0 ||
            rl.rlim_cur != (rlim_t)cfg->fsize ||
            rl.rlim_max != (rlim_t)cfg->fsize) {
            set_err(err, errlen,
                    "RLIMIT_FSIZE readback does not match requested %llu",
                    cfg->fsize);
            return -1;
        }
    }
    return 0;
}

int husk_security_prepare_init(char *err, size_t errlen)
{
    uint64_t caps;

    if (set_securebits(err, errlen) < 0)
        return -1;
    if (drop_bounding_except(HUSK_INIT_TEMP_CAPS, err, errlen) < 0)
        return -1;
    if (set_caps(HUSK_INIT_TEMP_CAPS) < 0) {
        set_err(err, errlen, "set init capabilities: %s", strerror(errno));
        return -1;
    }
    if (clear_ambient(err, errlen) < 0)
        return -1;
    if (get_caps(&caps) < 0 || caps != HUSK_INIT_TEMP_CAPS) {
        set_err(err, errlen, "init capability readback mismatch");
        return -1;
    }
    if (set_no_new_privs(err, errlen) < 0)
        return -1;
    if (install_seccomp(err, errlen) < 0)
        return -1;
    return 0;
}

int husk_security_workload_drop(char *err, size_t errlen)
{
    uint64_t caps;

    if (clear_ambient(err, errlen) < 0)
        return -1;
    if (drop_bounding_except(0, err, errlen) < 0)
        return -1;
    if (set_caps(0) < 0) {
        set_err(err, errlen, "clear workload capabilities: %s",
                strerror(errno));
        return -1;
    }
    if (get_caps(&caps) < 0 || caps != 0) {
        set_err(err, errlen, "workload capability readback mismatch");
        return -1;
    }
    if (set_no_new_privs(err, errlen) < 0)
        return -1;
    return 0;
}

int husk_security_init_finalize(char *err, size_t errlen)
{
    uint64_t caps;

    if (drop_bounding_except(HUSK_INIT_FINAL_CAPS, err, errlen) < 0)
        return -1;
    /* Clear ambient while CAP_SETPCAP is still effective; setting the final
     * CAP_KILL-only set would otherwise remove the capability needed here. */
    if (clear_ambient(err, errlen) < 0)
        return -1;
    if (set_caps(HUSK_INIT_FINAL_CAPS) < 0) {
        set_err(err, errlen, "set final init capabilities: %s",
                strerror(errno));
        return -1;
    }
    if (get_caps(&caps) < 0 || caps != HUSK_INIT_FINAL_CAPS) {
        set_err(err, errlen, "final init capability readback mismatch");
        return -1;
    }
    return 0;
}
