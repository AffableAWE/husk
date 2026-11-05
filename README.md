# husk

`husk` is a small Linux container runtime written in C. It runs a command
against a supplied root filesystem in new mount, PID, UTS, IPC, and network
namespaces using `pivot_root`, with optional cgroup v2 controls, rlimits, a
capability policy, `no_new_privs`, an architecture-checked seccomp filter, and
optional privileged bridge networking. `--rootless` additionally creates a
user namespace and maps container UID/GID 0 to the invoking ordinary user.

> **Security warning**
>
> This is a plumbing MVP, not a production sandbox. Privileged mode retains
> host root outside the container. Rootless mode reduces host privilege through
> a user namespace but is still a denylist-based hardening baseline. Do not run
> untrusted or hostile workloads with it.

## Prerequisites and host preparation

| Item | Requirement |
| --- | --- |
| CPU | x86-64 or aarch64 (the seccomp filter is written for these two) |
| Kernel | Linux with mount, PID, UTS, IPC, network, and user namespaces; cgroup v2 for resource limits |
| Build | C17 compiler (`gcc` or `clang`), GNU `make`; glibc or musl (on Alpine, also `linux-headers`) |
| Rootfs fixture | A statically linked `busybox` on `PATH` (Debian/Ubuntu package `busybox-static`; commonly `/bin/busybox` or `/usr/bin/busybox`) |
| Privileged runtime | Root in the initial user namespace (`CAP_SYS_ADMIN`); bridge networking also needs `CAP_NET_ADMIN` |
| Rootless runtime | An ordinary non-root account, unprivileged user namespaces enabled, and a caller-owned rootfs |
| Optional tests | `procps`, `util-linux` (`setpriv`), `iproute2`, `cppcheck`, Python 3 |

The documented development path uses a privileged Debian container only to get
a Linux kernel and the packages above:

```sh
docker build -f tests/Dockerfile.dev -t husk-dev .
docker run --rm --privileged -v "$PWD":/work -w /work husk-dev make check
```

That container is **host preparation for testing**, not a husk requirement.
The runtime itself is a single executable. Rootless execution does **not** use
`sudo` or a privileged helper; it is started directly by the ordinary user.
The privileged/rootless split is:

| Action | Privileged | Rootless |
| --- | --- | --- |
| Build | any user | any user |
| Prepare rootfs | root or user | user-owned copy |
| Run | root | non-root; `--rootless` required |
| Cgroup limits | writable delegated cgroup v2 directory | user-writable delegated subtree |
| Bridge networking | root + `CAP_NET_ADMIN` + an existing bridge | refused with exit 125 |

## Build

```sh
make                 # GCC/cc
make CC=clang        # Clang
make clean
```

The build uses `-std=c17 -Wall -Wextra -Wformat=2 -Wvla`. Add `WERROR=1` to
treat warnings as errors (CI does this). The binary is `./husk`; the version is
`husk 0.3.0`.

## Prepare a rootfs

```sh
make rootfs          # creates build/rootfs
```

`tests/make-rootfs.sh` builds a small fixture from a statically linked
`busybox`. In the tested environment it comes from the Debian bookworm package
`busybox-static` (GPL-2.0); the script finds it with `command -v busybox`,
prints the path and `ldd` output, and installs it as
`build/rootfs/bin/busybox`. A static busybox reports “not a dynamic
executable”, so the fixture needs no shared libraries. Applet symlinks for
`sh`, `cat`, `ip`, `ping`, and others are created under `bin/`.

Rootfs requirements:

* It must exist, be a directory, and must not be `/`.
* The command is resolved **inside the container**, after the filesystem
  switch. It may be absolute (`/bin/sh`), relative to the container root
  (`bin/sh`), or found in the fixed container `PATH` below. Container
  `execvp()` semantics apply, including absolute symlinks resolved against the
  container root and skipping non-executable early `PATH` candidates.
* A dynamic binary needs its loader and libraries inside the rootfs. A missing
  loader or shebang interpreter is reported after setup with exit `127`.
* `/proc` is mounted by husk. If the rootfs has no `/proc` directory, husk
  creates one (`0555`); that is the only intentional rootfs mutation. The rootfs
  must be writable in that case.
* `/dev` is **not** populated by this MVP. There is no `/dev/null`; commands
  that need device nodes may fail. `/sys` and cgroup filesystems are not
  mounted.
* Rootless mode requires a trusted rootfs that the invoking user can read and
  traverse. A user-owned copy of `build/rootfs` is the recommended test input;
  `tests/rootless.sh` makes such a copy.
* The fixture and rootfs are trusted. Symlinks inside a rootfs are not
  validated against escape; the isolation boundary is not implemented.

## Run

```sh
# Privileged mode (root):
sudo ./husk run --rootfs build/rootfs -- /bin/sh
sudo ./husk run --rootfs build/rootfs -- /bin/sh -c 'echo hello; exit 7'
sudo ./husk run --rootfs build/rootfs --hostname demo -- /bin/sh -c 'hostname; echo $$'

# Rootless mode (ordinary user, no sudo):
./husk run --rootless --rootfs /path/to/user/rootfs -- /bin/sh -c 'id; hostname'
./husk run --rootless --rootfs /path/to/user/rootfs -- /bin/sh -c 'exit 7'
./husk --help
```

`--` separates husk options from the workload command. It is optional when the
command does not start with `-`. `--rootfs=DIR`, `--hostname=NAME`,
`--rootless`, and the resource options are also accepted in any option
position before the command. The container `PATH` is fixed to
`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`; `HOME`
defaults to `/root`; other host environment variables are inherited.

### Delegated cgroups and rlimits

```sh
# Privileged with an explicitly delegated cgroup v2 parent:
sudo ./husk run --rootfs build/rootfs \
  --cgroup-parent /sys/fs/cgroup/husk \
  --memory-max 67108864 --pids-max 64 --cpu-max 50000 100000 \
  --rlimit-nofile 256 --rlimit-fsize 1048576 \
  -- /bin/sh -c 'ulimit -n; cat /proc/self/cgroup'

# Rootless on a delegated subtree:
./husk run --rootless --rootfs /path/to/user/rootfs \
  --cgroup-parent /sys/fs/cgroup/user.slice/husk \
  --memory-max 33554432 --pids-max 32 -- /bin/sh
```

`--memory-max`/`--pids-max`/`--cpu-max` require an explicit
`--cgroup-parent`; there is no inferred default. `--cpu-max` takes quota and
period in microseconds. `--rlimit-nofile` (minimum 16) and `--rlimit-fsize`
(bytes) are applied to the workload. Values are decimal integers. The parent
directory must be writable by the caller and the requested controllers must be
available; otherwise setup fails with exit 125 rather than silently disabling
the limit.

### Optional existing-bridge networking (privileged)

```sh
sudo ./husk run --rootfs build/rootfs \
  --bridge huskbr0 --container-address 10.88.0.2/24 \
  --gateway 10.88.0.1 --lease-dir /var/lib/husk/leases \
  -- /bin/sh -c 'ip addr; ip route'
```

The bridge must already exist and be up, and the lease directory must already
exist and be writable by the caller. husk creates only its own veth pair,
attaches the host end to that bridge, moves the peer into the container, and
deletes the veth on exit. Addresses are reserved with file-backed leases;
duplicate live addresses are rejected, and stale leases from a crashed parent
are recovered under an advisory lock. Bridge mode is privileged-only and
IPv4-only; there is no bridge creation, NAT, or firewall policy.

### Exit status

| Status | Meaning |
| --- | --- |
| `0..125` | Workload's own exit status |
| `125` | Namespace, mount, user-namespace mapping, `pivot_root`, `/proc`, cgroup, or network setup failure |
| `126` | Command found but could not be executed (also possible workload status) |
| `127` | Command not found in the rootfs (also possible workload status) |
| `2` | Invalid invocation, missing command, invalid rootfs, or mode-selection error |
| `128+N` | Container init or workload killed by signal `N` |

`husk` prints `husk: workload terminated by signal N (...)` to stderr when the
workload dies from a signal. If the container init is killed, the parent prints
a similar message. `SIGKILL` cannot be forwarded; killing the parent tears the
container down through `PR_SET_PDEATHSIG`.

## Lifecycle, isolation, and cleanup

### Process lifecycle

* The parent calls `clone()` with `CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS |
  CLONE_NEWIPC | CLONE_NEWNET | SIGCHLD`. Rootless mode also sets
  `CLONE_NEWUSER`, so the user namespace is created first and owns the other
  new namespaces.
* Rootless mapping: the child sends `HUSK_MSG_MAP_REQUEST` over a
  `SOCK_SEQPACKET` control socket. The parent writes
  `/proc/<child>/uid_map` (`0 <caller-uid> 1`), writes `deny` to
  `/proc/<child>/setgroups`, writes `/proc/<child>/gid_map`
  (`0 <caller-gid> 1`), then acknowledges with `HUSK_MSG_MAP_READY`. On
  failure it sends `HUSK_MSG_MAP_ERROR`, kills, and reaps the child. Both
  sides bound this exchange to 10 seconds.
* Parent and container init explicitly install a waitable-child `SIGCHLD`
  disposition (`SIG_DFL`) before creating children, normalizing an inherited
  `SIGCHLD=SIG_IGN`.
* The cloned process is PID 1 in the new PID namespace and acts as a minimal
  init. It forks the workload, which runs as PID 2.
* PID 1 forwards `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGTERM`, `SIGUSR1`, and
  `SIGUSR2` to the workload, reaps orphaned descendants, and after the
  workload exits sends `SIGKILL` to remaining namespace processes before
  exiting.
* The parent blocks forwarded signals and uses `signalfd`, so forwarding is
  not lost to handler races. It waits for the init and propagates the workload
  status.
* The post-mapping setup wait is bounded at 30 seconds; on timeout or a
  malformed/EOF handshake the parent kills and reaps the init. `execvp()`
  failure is reported through a close-on-exec pipe.
* If the parent is killed, `PR_SET_PDEATHSIG` kills the container init; the
  kernel then tears down the PID namespace and its processes. Killing the init
  also tears down the namespace.

### Filesystem setup (inside the new mount namespace)

1. `mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)` stops propagation.
2. The supplied rootfs is recursively bind-mounted onto itself.
3. `chdir(rootfs)`; `pivot_root(".", ".")`; `umount2(".", MNT_DETACH)`
   detaches the old root without creating an `.oldroot` directory.
4. `/proc` is mounted `MS_NOSUID | MS_NOEXEC | MS_NODEV`. Privileged mode
   mounts it after the pivot. Rootless mode mounts it on the new root's `proc`
   directory before `pivot_root` because the post-pivot mount fails with
   `EPERM` in an unprivileged user namespace on the tested kernel; the child
   is already PID 1, so the earlier mount still describes the container's PID
   namespace.
5. `sethostname()` sets the hostname in the private UTS namespace.

Every mount happens in the child's private mount namespace; no mount is
visible under the rootfs path from the host after the run.

### Isolation and security policy

Namespace isolation is the primary boundary: mount, PID, UTS, IPC, and network
namespaces in both modes, plus a user namespace in rootless mode. Policy
**husk-minimal-v1** is applied to every launch:

* After setup the init keeps only `CAP_KILL` in effective, permitted,
  inheritable, and bounding sets; ambient is empty. A temporary `CAP_SETPCAP`
  is used only until workload exec is confirmed.
* The workload drops all five capability sets to empty before `execve`;
  `no_new_privs=1` is set in the init and inherited.
* Securebits are `NOROOT|NOROOT_LOCKED|NO_SETUID_FIXUP|NO_SETUID_FIXUP_LOCKED`.
* An architecture-validated seccomp filter (aarch64/x86_64) is installed in
  the init before `fork` and inherited by the workload. It denies namespace
  creation (`clone` namespace flags, `unshare`, `setns`), mount/pivot/chroot,
  tracing (`ptrace`, `process_vm_*`, `pidfd_getfd`), BPF, module/kexec, perf,
  keyrings, handle-based opens, userfaultfd, io_uring, swap/reboot/hostname,
  and the new mount API. Ordinary file, process, signal, and socket syscalls
  remain allowed.
* `clone3` returns `ENOSYS` rather than `EPERM`; libc falls back to `clone(2)`
  for ordinary threads, while `clone(2)` still rejects namespace flags. On
  x86-64, syscall numbers with the x32 bit are explicitly rejected.

This is a denylist, not a complete seccomp allowlist. 32-bit compat syscalls
and `clone3`-only programs are incompatible. The policy is a hardening
baseline, not a production sandbox.

### Network

The default network namespace contains kernel-created inactive tunnel devices
and a down loopback interface, but no external interface, IP address, or route,
so there is no external connectivity. With `--bridge` (privileged), husk adds
one veth pair, attaches the host end to the named existing bridge, configures
the supplied IPv4 address and default route, and removes the veth and lease on
exit. Rootless mode always keeps isolated networking and refuses `--bridge`.

### Cleanup and ownership

| Resource | Owner | Cleanup |
| --- | --- | --- |
| Control socketpair | Parent and init | Closed on both sides during normal flow |
| Clone stack (`mmap`) | Parent | `munmap` immediately after `clone` |
| `signalfd` | Parent | Closed before exit |
| Mount/PID/UTS/IPC/net namespaces | Kernel | Destroyed when PID 1 exits |
| User namespace and single-ID maps (rootless) | Kernel | Destroyed when PID 1 exits |
| Rootfs bind mount, old-root mount, `/proc` mount | Child mount namespace | Destroyed with the namespace |
| `/proc` directory in rootfs | Rootfs | Persistent only if husk created it |
| Processes | PID namespace | Workload reaped; descendants killed when init exits |
| cgroup `husk.XXXXXX` | Parent | Removed after normal exit and setup rollback; empty, owner-dead stale directories recovered at startup |
| Bridge lease and veth | Parent | Lease released and veth deleted on exit; stale leases recovered under lock |

Kernel objects (namespaces, veths, cgroups) do not survive a host reboot.
Persistent lease files can remain after a crash; stale leases are recovered
under an advisory lock. Abrupt cases that remain: no diagnostic is produced
when the parent is `SIGKILL`ed, and there is no broad persistent recovery state
beyond the tested cgroup/lease cleanup.

The test harness has separate ownership protection (`tests/owned_run.c`): it
runs each long-lived invocation under a supervisor in its own session/process
group, records the owner identity, observes results before releasing the
group, and refuses to signal unverified numeric process-group IDs. It is
test-only and does not affect the runtime.

## Supported workloads

Static binaries, dynamic binaries with their loader/libraries in the rootfs,
and scripts whose interpreter is present in the rootfs. Commands are resolved
by container-side `execvp` after the filesystem switch. Workloads that need
`/dev`, `/sys`, a TTY, job control, terminal resize, or a network route other
than the optional IPv4 bridge are not supported by this MVP. The workload
inherits the caller's environment except `PATH` and `HOME` defaults and runs
with the capability/seccomp policy above.

## Known limitations

* **Not a production sandbox.** Privileged mode is host root; rootless mode is
  a reduced-privilege user namespace, not a completed security boundary. LSM
  policy, image validation, and firewall policy are absent.
* **Single-ID rootless mapping.** Container UID/GID 0 map to the caller's
  UID/GID. Other container IDs are unmapped (overflow `65534`); no
  `subuid`/`subgid` ranges or `newuidmap`/`newgidmap` helpers.
* **Supplementary groups are inherited but not mapped.** They can still
  participate in host file permission checks while displayed as overflow GID
  inside.
* **Unprivileged user namespaces must be enabled.** A denial returns exit 125;
  there is no fallback to privileged mode. Root invoking `--rootless` is
  refused, and an ordinary user invoking privileged mode is refused.
* **Rootfs is trusted.** Ownership and symlink escape are not validated.
* **Rootless `/proc` ordering differs**, as described above.
* **Seccomp is a denylist.** 32-bit compat and `clone3`-only programs are
  incompatible.
* **Bridge networking is IPv4-only**, requires an existing bridge,
  `CAP_NET_ADMIN`, and a lease directory; there is no bridge creation, NAT,
  IPv6, port forwarding, or firewall policy.
* **No `/dev` population, `/sys`, masked/read-only paths, TTY allocation, job
  control, terminal resize, image registries, Docker compatibility, or
  orchestration.** Memory OOM-kill was not observed under swap.
* **Ambiguous exit statuses.** `125`, `126`, and `127` can also be workload
  statuses; stderr text disambiguates. `--` is optional for commands that do
  not begin with `-`.
* **Signal/environment edges.** The workload inherits the caller's process
  group, so terminal `^C` can reach it directly as well as through husk.
  Signals during the short setup handshake are queued. Other host environment
  variables are inherited. Command resolution is deliberately late.
* **x86-64 and aarch64 only.** Other CPUs fail at build time on purpose,
  because the seccomp filter has no syscall table for them.

## Testing

```sh
make WERROR=1 && make rootfs
sudo make check            # privileged smoke suite
tests/rootless.sh          # rootless suite, run as an ordinary user
```

The resource, security, bridge, and repeated-launch suites need cgroup v2 and
a bridge, so they run inside a privileged Docker container:

```sh
docker build -f tests/Dockerfile.dev -t husk-dev .
tests/stage34-docker.sh gcc                      # cgroups, rlimits, capabilities, seccomp
tests/stage5-docker.sh gcc                       # bridge networking
HUSK_CAMPAIGN_ITERS=1000 tests/stage6-docker.sh gcc   # 1,000-launch cleanup campaign
```

Results (pass / fail / skip):

| Suite | aarch64 (Debian 12, GCC 12, Clang 14) | x86-64 (Ubuntu 24.04, GCC 13, Clang 18) |
| --- | --- | --- |
| Privileged smoke | 138 / 0 / 0 | 138 / 0 / 0 |
| Rootless | 148 / 0 / 0 | 148 / 0 / 0 |
| Resources and security, privileged | 65 / 0 / 1 | not run |
| Resources and security, rootless | 67 / 0 / 0 | not run |
| Bridge networking | 31 / 0 / 0 | not run |
| 1,000-launch cleanup campaign | 36 / 0 privileged, 24 / 0 rootless | not run |
| ASan/UBSan smoke | 138 / 0 / 0 | not run |
| cppcheck | clean | clean |

The one skip is a rootless-only case in the privileged run. The x86-64 host had
no cgroup v2, so the cgroup-based suites were not run there.

CI (`.github/workflows/ci.yml`) builds with GCC and Clang on Ubuntu 24.04 with
`WERROR=1`, then runs the privileged smoke suite and cppcheck.

### Performance

Startup time on aarch64 (8 vCPU, GCC 12), 1,000 launches of `/bin/true` with
cgroup limits, capabilities, `no_new_privs`, and seccomp enabled. Startup is
measured from before `fork` until the workload has called `exec`.

| Configuration | Startup median / p95 / p99 (ms) |
| --- | --- |
| Privileged, isolated network | 2.83 / 5.78 / 8.79 |
| Privileged, bridge network | 36.33 / 46.64 / 59.22 |
| Rootless, isolated network | 2.47 / 6.95 / 10.88 |

Creating and removing the veth pair takes most of the time in bridge mode.
To reproduce:

```sh
PERF_ITERS=1000 PERF_OUT=run tests/perf-docker.sh gcc
python3 tests/perf_stats.py 'build/evidence/perf/run-*.csv'
```

## Not implemented (deferred)

* Multi-ID mappings, `subuid`/`subgid` delegation, `newuidmap`/`newgidmap`
* Broader seccomp allowlists, LSM policy, capability tuning
* Cgroup delegation helpers, swap/IO/other controllers
* IPv6, NAT, port forwarding, bridge creation, firewall policy
* `/dev` population, `/sys`, masked/read-only paths
* TTY allocation, job control, terminal resize
* Image registries, Docker compatibility, orchestration
* Comprehensive crash recovery beyond the tested cgroup/lease paths

## Repository layout

```text
src/       runtime (main, namespaces, cgroups, security, network)
tests/     test suites, probes, rootfs builder, perf tools
.github/   CI workflow
```

Build output (`husk`, `src/*.o`, and everything under `build/`) is generated
and ignored by git.
