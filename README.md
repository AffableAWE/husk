# husk

A small Linux container runtime written in C. Run a command inside a supplied
root filesystem and see how Linux container primitives fit together.

Husk creates separate mount, PID, hostname, IPC, and network namespaces. It
supports rootless execution, optional cgroup v2 resource limits, and privileged
IPv4 bridge networking. Workloads run with dropped capabilities,
`no_new_privs`, and a seccomp filter.

**An educational runtime for trusted workloads.** The rootfs is trusted input;
the security policy is a hardening baseline. Husk is not a production sandbox
or a Docker replacement.

## Quick start

Requires Linux on x86-64 or aarch64, a C17 compiler, GNU Make, and a static
BusyBox for the example rootfs. On Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y git build-essential busybox-static
git clone https://github.com/AffableAWE/husk.git
cd husk
make
make rootfs
```

Run as an ordinary user with unprivileged user namespaces enabled:

```sh
./husk run --rootless --rootfs build/rootfs -- /bin/sh -c 'id; hostname; echo hello'
```

Or use privileged mode on a Linux development machine:

```sh
sudo ./husk run --rootfs build/rootfs -- /bin/sh -c 'echo hello'
```

Build and prepare the rootfs as your ordinary user for the rootless example.
macOS and Windows need a Linux VM; the [Docker development setup](docs/runtime.md#docker-development-environment)
provides another way to try the project.

## What is included

- A host supervisor and a container init that forwards signals and reaps children.
- Single-ID rootless UID/GID mapping, without privileged mapping helpers.
- Optional memory, task-count, CPU, open-file, and file-size limits.
- Optional veth networking through an existing IPv4 bridge; isolated networking is the default.

There is no image downloading, OCI bundle support, TTY allocation, or automatic
internet access. `/dev` and `/sys` are not populated. See the
[runtime reference](docs/runtime.md) for options, prerequisites, and limitations.

## Development

```sh
make clean
make WERROR=1
make rootfs
sudo make check       # privileged smoke suite; Linux required
tests/rootless.sh     # separate suite; run as an ordinary user
```

CI builds with GCC and Clang, runs the privileged smoke suite, and checks the
source with cppcheck. Additional resource, networking, and lifecycle suites
are described in the [runtime reference](docs/runtime.md#tests-and-performance).



