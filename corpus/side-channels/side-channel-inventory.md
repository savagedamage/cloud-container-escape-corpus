# Container Side-Channel Inventory

## Overview
Comprehensive mapping of information leakage paths and boundary violations in container runtimes, organized by attack surface.

## 1. Shared /proc Exposure

### /proc/sys/kernel/*
- **Leakage**: Kernel version, sysctl parameters, module info
- **Risk**: Recon for kernel exploit selection
- **Mitigation**: `hidepid=2,gid=<monitoring>` mount option, ProcFS masking

### /proc/<pid>/*
- **Leakage**: Host process cmdline, environ, fd/, maps, status, ns/
- **Risk**: Credential theft, lateral movement targeting, namespace mapping
- **Detection**: Audit `openat` on `/proc/*/environ`, `/proc/*/cmdline`
- **Mitigation**: PID namespace isolation, `hidepid=2`, drop CAP_SYS_PTRACE

### /proc/self/ns/
- **Leakage**: Namespace inode numbers (pid, net, mnt, uts, ipc, cgroup, user, time)
- **Risk**: Namespace escape via `setns(2)`, cross-namespace attacks
- **Mitigation**: Hide host `/proc`, user namespace mapping

## 2. Shared /sys Exposure

### /sys/kernel/*
- **Leakage**: Kernel tunables, security module state (SELinux, AppArmor), BPF maps
- **Risk**: Security policy bypass detection, eBPF attack surface
- **Mitigation**: Read-only `/sys` mounts, drop CAP_SYS_ADMIN

### /sys/fs/cgroup/*
- **Leakage**: cgroup hierarchy, controllers, memory/CPU limits, ancestor cgroups
- **Risk**: cgroup escape (release_agent), resource exhaustion, container detection
- **Mitigation**: cgroup v2 unified hierarchy, `cgroupns=host` only when needed

### /sys/bus/* / /sys/devices/*
- **Leakage**: Hardware topology, device drivers, IOMMU groups
- **Risk**: Device passthrough abuse, DMA attacks, side-channel targeting
- **Mitigation**: Device cgroup controller, no device mounts

## 3. cgroup v2 Hierarchy Analysis

### Delegated cgroup Subtrees
- **Leakage**: Container's cgroup path, parent hierarchy, sibling containers
- **Risk**: cgroup notification abuse, sibling DoS, resource manipulation
- **Detection**: Monitor `cgroup.procs` writes, `cgroup.subtree_control` changes

### cgroup.controllers / cgroup.subtree_control
- **Leakage**: Available controllers (cpu, memory, io, pids, cpuset, hugetlb, misc)
- **Risk**: Controller delegation abuse, resource isolation bypass

### cgroup.events / cgroup.freeze
- **Leakage**: Frozen state, population events
- **Risk**: Freeze/thaw for stealth, population tracking for orchestration

## 4. Namespace Boundary Analysis

### nsenter / nsjail Boundaries
- **Tool**: `nsenter -t <pid> -a` — enter all namespaces of target PID
- **Risk**: Full namespace escape if CAP_SYS_ADMIN + host PID access
- **Detection**: Audit `setns`, `unshare`, `clone` with CLONE_NEW* flags

### User Namespace Mapping
- **Leakage**: UID/GID maps in `/proc/<pid>/uid_map`, `gid_map`
- **Risk**: Map manipulation for privilege escalation, host UID 0 access
- **Mitigation**: Single UID/GID map entry, no nested user namespaces

### Network Namespace Leakage
- **Leakage**: Host network interfaces, routing tables, iptables/nftables rules
- **Risk**: Network recon, firewall bypass, service discovery
- **Mitigation**: Dedicated pod network namespace, CNI isolation

## 5. Seccomp Notch Analysis

### Default Docker Seccomp Profile Gaps
| Syscall | Risk | Why Not Blocked |
|---------|------|-----------------|
| `bpf` | eBPF injection | Legitimate tracing |
| `pidfd_getfd` / `pidfd_open` | FD theft | Debugging use cases |
| `userfaultfd` | Kernel exploit | Memory management |
| `io_uring_setup` / `enter` | Kernel exploit | Async I/O performance |
| `clone3` / `clone` | Namespace escape | Thread creation |
| `setns` | Namespace escape | Legitimate nsenter |
| `mount` / `umount2` | Filesystem escape | Volume management |
| `ptrace` | Process injection | Debugging |

### Seccomp Bypass Techniques
- **Seccomp notify FD**: Delegate to userspace agent (CRI-O/containerd)
- **TSYNC race**: Thread sync bypass via `SECCOMP_FILTER_FLAG_TSYNC`
- **Notifier injection**: Malicious notifier process
- **Arch mismatch**: x32 vs x64 syscall table differences

### Custom Profile Recommendations
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {"names": ["bpf", "pidfd_getfd", "pidfd_open", "userfaultfd", "io_uring_setup", "io_uring_enter", "io_uring_register", "process_vm_readv", "process_vm_writev", "kcmp", "bpf"], "action": "SCMP_ACT_ERRNO"}
  ]
}
```

## 6. Runtime Socket Exposure

### Docker/containerd/cri-o Sockets
- **Paths**: `/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/run/crio/crio.sock`
- **Leakage**: Full container lifecycle control, image pull, exec, logs
- **Risk**: Container escape, crypto-miner deployment, lateral movement
- **Detection**: Socket connection monitoring, unusual API calls

### Kubelet Read-Only Port (10255)
- **Leakage**: Pod specs, node info, metrics
- **Risk**: Recon, credential extraction from pod env
- **Mitigation**: Disable read-only port, use authenticated 10250

## 7. Filesystem Layer Leakage

### OverlayFS / devicemapper Lowerdirs
- **Leakage**: Base image layers, hidden files in lower dirs
- **Risk**: Secret extraction from "deleted" layers, supply chain analysis
- **Tool**: `dive`, `container-diff`, custom layer walker

### /etc/hosts / /etc/resolv.conf Injection
- **Leakage**: Service discovery, DNS manipulation
- **Risk**: MITM, service hijacking
- **Mitigation**: Read-only rootfs, HostAliases instead of hosts manipulation

## 8. Capability Effective Set Leakage

### Capability Introspection
- **Source**: `/proc/self/status` (CapEff, CapPrm, CapInh, CapBnd)
- **Risk**: Attacker enumerates exact capability set for chain building
- **Mitigation**: Minimal capability sets, drop ALL by default

## 9. Time Namespace / VDSO Leakage

### Clock Sources
- **Leakage**: Host time vs container time drift, VDSO mapping
- **Risk**: Timing side-channels, TSC-based attacks
- **Mitigation**: Time namespace (Linux 5.6+), `clocksource` isolation

## 10. Audit & Detection Matrix

| Side-Channel | Detection Method | Tooling |
|-------------|------------------|---------|
| /proc access | auditd, Falco, Tetragon | `auditctl -w /proc -p r` |
| /sys access | auditd, Falco | `auditctl -w /sys -p r` |
| cgroup writes | Falco, cgroup notifications | `cgroup-tools` |
| setns/clone | auditd, Falco, Tetragon | `auditctl -a exit,always -F arch=b64 -S setns` |
| seccomp notify | CRI logs, Falco | containerd CRI plugin logs |
| socket access | systemd socket activation, Falco | `ss -lxp` monitoring |
| capability use | auditd, Falco | `auditctl -a exit,always -F arch=b64 -S capset` |

## References
- Linux Namespaces (man 7 namespaces)
- cgroup v2 Documentation (kernel.org)
- Seccomp BPF (kernel.org)
- Falco Rules Library
- Tetragon eBPF Security Observability
