---
id: CE-006
name: eBPF probe injection
category: kernel/ebpf
mitre_attack: [T1556.002, T1055, T1040]
risk: medium
detection_rules: [SIGMA-006, FALCO-006]
---

# CE-006 — eBPF probe injection

## Summary

eBPF lets unprivileged-in-practice code run inside the kernel's BPF VM: hook
syscalls, read socket buffers, log keystrokes, or tamper with kernel data
structures — no kernel module, no reboot, no crash. A container with `CAP_BPF`
(+ `CAP_SYS_ADMIN` or `CAP_PERFMON`) can load tracing and networking programs
that observe or alter host-wide behavior.

## Prerequisites

- Kernel ≥ 5.8 with BPF JIT (`net.core.bpf_jit_enable=1`)
- `CAP_BPF` plus `CAP_SYS_ADMIN` (or `CAP_PERFMON` for read-only tracing)
- `bpf()` syscall not blocked by seccomp

## Attack path

1. Load a `kprobe`/`tracepoint` program on `tcp_sendmsg` / `read` syscalls
2. Attach a socket filter to capture host traffic via the loopback/eth0
3. Use maps to exfiltrate observed data (read via a userland helper)
4. Persist by pinning the program to a bpffs (survives process exit)

## PoC sketch

```bash
# kernel symbols visible? (kallsyms exposure)
grep ' _text' /proc/kallsyms | head -3

# with bpftool + CAP_BPF: attach a tracing program
bpftool prog load probe.o /sys/fs/bpf/probe
bpftool prog attach pinned /sys/fs/bpf/probe tracepoint syscalls sys_enter_read

# socket filter for network sniffing (classic BPF, no caps needed beyond NET_RAW)
tcpdump -i eth0 -w /tmp/cap.pcap
```

Malicious examples (public research): eBPF keyloggers hooking `read` on TTYs,
eBPF rootkits hiding PIDs from `/proc`, and sockmap-based exfiltration. All of
these load through the same `bpf()` syscall path.

## Detection

- **Logs:** `bpf()` syscall audit trail; BPF program ID enumeration
  (`bpftool prog list`) drift against a baseline
- **Sigma:** `SIGMA-006` — bpftool/bcc program load commands
- **Falco:** `FALCO-006` — evt.type `bpf` with prog load
- **Forensics:** compare pinned `/sys/fs/bpf` programs against known-good set

## Mitigation

- Drop `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` from workloads
- Seccomp: deny `bpf()` unless the workload genuinely needs it
- `kernel.unprivileged_bpf_disabled=2` where possible
- Enforce signed BPF programs (BPF token / kfunc allowlists) on modern kernels

## References

- Kernel BPF documentation (docs.kernel.org/bpf)
- Public eBPF rootkit research (boopathi, evilsocket et al.)
- MITRE ATT&CK T1040 (Network Sniffing), T1556.002 (Password Filter)
