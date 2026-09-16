---
id: CE-010
name: Capability-based escape chains
category: kernel/capabilities
mitre_attack: [T1611, T1068]
risk: high
detection_rules: [SIGMA-007, SIGMA-008, FALCO-007]
---

# CE-010 — Capability-based escape chains

## Summary

The grand unified theory of Linux container escapes: individual capabilities
are small, but chains are lethal. Every "advanced" technique in this taxonomy
is ultimately a capability story. This entry catalogs the most dangerous
single-capability → host-impact mappings.

## Prerequisites

- A capability (or set) not dropped by the runtime
- The corresponding syscall not blocked by seccomp
- A reachable host resource (mount, module, process, file)

## Capability → abuse map

| Capability | Abuse → host impact |
|---|---|
| `CAP_SYS_ADMIN` | mount host devices, pivot_namespaces, cgroup release_agent (CE-001), `setns` (CE-009) |
| `CAP_SYS_PTRACE` | inject into host processes, `pidfd_getfd` (CE-002), credential dump |
| `CAP_DAC_OVERRIDE` / `CAP_DAC_READ_SEARCH` | read `/etc/shadow`, host SSH keys, any file regardless of mode |
| `CAP_SYS_MODULE` | load kernel modules — direct kernel code execution (rootkit) |
| `CAP_SYS_RAWIO` | raw disk access — rewrite host filesystem on disk |
| `CAP_NET_ADMIN` | manipulate host routing/iptables — traffic redirection, MITM |
| `CAP_NET_RAW` | raw sockets — packet sniffing/spoofing on host networks |
| `CAP_SETUID`/`CAP_SETGID` | `setuid(0)` — root-in-container (user-ns quirk) |
| `CAP_BPF`/`CAP_PERFMON` | eBPF probe injection (CE-006) |
| `CAP_SYS_CHROOT` | chroot into mounted host root (CE-007) |
| `CAP_MKNOD` | create device nodes → access host block devices |

## PoC sketch

```bash
# CAP_DAC_OVERRIDE: read the shadow file from a mounted host root
cat /host/etc/shadow

# CAP_SYS_MODULE: load a kernel module (staged into /host)
insmod /host/tmp/pwn.ko

# CAP_SYS_CHROOT + host root mount
chroot /host /bin/sh

# CAP_SETUID in a user namespace: uid 0 inside, but the bounding set decides
id; capsh --print | grep -E 'Current|Bounding'
```

`capsh --print` (libcap2-bin) inside a container is the single most useful
triage command: it dumps the effective/permitted/inheritable/bounding/ambient
sets in one line each.

## Detection

- **Baselines:** `runtime-baseline` (this corpus) snapshots CapEff/CapPrm/
  CapInh/CapBnd/CapAmb + seccomp mode; any drift fires CRITICAL
- **Logs:** auditd `capset` syscalls, `cap_effective` changes
- **Sigma:** `SIGMA-007` (insmod/modprobe), `SIGMA-008` (shadow reads)
- **Falco:** `FALCO-007` (kernel module load)

## Mitigation

- Drop `ALL` capabilities, add back only what the workload needs
- Seccomp + AppArmor/SELinux as a second layer (defense in depth)
- `no_new_privs` in container configs (frozen capability sets)
- Enforce via PodSecurity Restricted + admission policies

## References

- capabilities(7) man page
- MITRE ATT&CK T1611, T1068
