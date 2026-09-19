# Container Escape Lab Setup

Reproducible lab for testing escape techniques and the corpus tooling. All configurations are deliberately vulnerable — run ONLY in an isolated VM.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Isolated Lab VM (min 4GB RAM, 2 vCPU)          │
│                                                 │
│  kind / k3d single-node cluster                 │
│  ├── default ns: escape-test pods               │
│  ├── vulnerable ns: privileged pods + hostPath  │
│  └── secure ns: PodSecurity=Restricted          │
│                                                 │
│  Docker (host)                                  │
│  └── dind container for runtime socket abuse    │
│                                                 │
│  containerd (default CRI)                       │
│  └── socket: /run/containerd/containerd.sock    │
└─────────────────────────────────────────────────┘
```

## Prerequisites

- Linux host with KVM or bare metal VM (do NOT run on daily-driver)
- Docker or Podman for image tooling
- kubectl
- kind or k3d

## 1. Create isolated VM

```bash
# libvirt example — no shared folders with host
virt-install --name escape-lab \
  --memory 4096 --vcpus 2 \
  --disk size=40,path=/var/lib/libvirt/images/escape-lab.qcow2 \
  --os-variant ubuntu24.04 \
  --network network=default \
  --cdrom /path/to/ubuntu-24.04-server.iso
```

## 2. Install tooling

```bash
# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install kubectl /usr/local/bin/

# kind
go install sigs.k8s.io/kind@latest
# or
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
chmod +x kind && sudo mv kind /usr/local/bin/

# Corpus tools (pip-installable)
git clone <your-corpus-repo> /opt/container-escape-corpus
pip install /opt/container-escape-corpus        # installs: escape-corpus, image-diff, runtime-baseline, admission-review

# OCI tooling for image-diff
go install github.com/google/go-containerregistry/cmd/crane@latest
sudo apt install skopeo libcap2-bin   # getcap for file capabilities
```

## 3. Create lab cluster

```bash
cat > /tmp/kind-config.yaml <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
EOF

kind create cluster --name escape-lab --config /tmp/kind-config.yaml
kubectl get nodes
```

## 4. Deploy vulnerable namespaces

```bash
# Vulnerable namespace (no PodSecurity admission)
kubectl create namespace vulnerable
kubectl label namespace vulnerable pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/warn=privileged --overwrite

# Secure namespace (PodSecurity Restricted)
kubectl create namespace secure
kubectl label namespace secure pod-security.kubernetes.io/enforce=restricted --overwrite
```

## 5. Scripted bring-up

The manual steps above (cluster + namespaces + pod matrix) are scripted and idempotent — re-running is safe (`set -euo pipefail`, every step no-ops when the target state exists):

```bash
./corpus/lab/up.sh        # create kind cluster + namespaces, apply lab manifests
./corpus/lab/verify.sh    # verify only — applies nothing
```

- `up.sh` creates the `escape-lab` kind cluster when absent (override with `LAB_CLUSTER_NAME`, wait with `LAB_KIND_WAIT`), ensures `vulnerable` (PodSecurity=privileged) and `secure` (PodSecurity=restricted) exist with the right labels, then `kubectl apply`s every `corpus/lab/*-pod.yaml`. If docker is not yet reachable in the shell it re-execs through `sg docker` when available, otherwise it tells you to run `newgrp docker` first.
- `verify.sh` runs `admission-review --pod <file> --json` for each manifest and asserts `risk_level` is `CRITICAL` or `HIGH`, printing `PASS`/`FAIL` per manifest and exiting non-zero if any manifest is under-detected. It then does a `runtime-baseline baseline` → `verify` round trip against the `<cluster>-control-plane` container (runtime `docker`) and expects `No drift detected`. The runtime half reports `SKIP` (not `FAIL`) when docker or the kind cluster are unavailable.

Fixture manifests — all in `namespace: vulnerable`, all currently detected `CRITICAL`:

| Manifest | Technique |
|----------|-----------|
| `privileged-escape-pod.yaml` | privileged container + SYS_ADMIN + host `/proc` |
| `docker-socket-pod.yaml` | runtime socket abuse via `docker.sock` |
| `hostpath-proc-pod.yaml` | host PID namespace abuse via `/proc` mount |
| `cgroup-release-agent-pod.yaml` | cgroup release_agent host code execution |
| `ebpf-probe-pod.yaml` | eBPF probe injection (CAP_BPF/CAP_SYS_ADMIN + bpffs) |
| `pidfd-getfd-pod.yaml` | cross-namespace fd theft (hostPID + SYS_PTRACE) |
| `capability-chain-pod.yaml` | DAC_OVERRIDE + SYS_MODULE capability chain |

## 6. Test pod matrix

```bash
# Privileged escape pod (vulnerable ns)
kubectl apply -f corpus/lab/privileged-escape-pod.yaml -n vulnerable

# Docker socket pod
kubectl apply -f corpus/lab/docker-socket-pod.yaml -n vulnerable

# hostPath /proc pod
kubectl apply -f corpus/lab/hostpath-proc-pod.yaml -n vulnerable

# cgroup release_agent pod
kubectl apply -f corpus/lab/cgroup-release-agent-pod.yaml -n vulnerable

# eBPF probe injection pod
kubectl apply -f corpus/lab/ebpf-probe-pod.yaml -n vulnerable

# pidfd_getfd pod (hostPID + SYS_PTRACE)
kubectl apply -f corpus/lab/pidfd-getfd-pod.yaml -n vulnerable

# capability-chain pod (DAC_OVERRIDE + SYS_MODULE)
kubectl apply -f corpus/lab/capability-chain-pod.yaml -n vulnerable

# ...or just apply every lab fixture at once
kubectl apply -f corpus/lab/

# Baseline tool on each pod
runtime-baseline baseline --container <pod> --runtime crictl --output baseline-<pod>.json
```

## 7. Escape technique validation matrix

| Technique | Pod config | Validation command | Expected result |
|-----------|-----------|-------------------|-----------------|
| Docker socket | docker-socket-pod | `docker -H unix:///var/run/docker.sock ps` | Host containers listed |
| hostPath /proc | hostpath-proc-pod | `nsenter -t 1 -a /bin/bash` | Host shell |
| cgroup release_agent | cgroup-release-agent-pod | standard PoC | Host code exec |
| eBPF probe injection | ebpf-probe-pod | load + attach a tracepoint probe | Probe runs in host kernel |
| pidfd_getfd | pidfd-getfd-pod | `pidfd_getfd` on a host PID's fd | Host fd duplicated |
| Capability chain | capability-chain-pod | `insmod` from the mounted module path | Module loaded in host kernel |
| K8s RBAC escalation | any pod + permissive SA | `kubectl auth can-i --list` | Impersonation paths |
| Seccomp bypass | privileged pod | probe syscalls | Blocked syscall list |

## 8. Admission review in CI

```bash
# Dry-run pod specs against built-in + custom policies
admission-review --pod deploy/pod.yaml --policies policies/kyverno-simplified.yaml --output report.json

# Gate: fail if CRITICAL findings
python3 -c "
import json
r = json.load(open('report.json'))
exit(1 if r['risk_level'] in ('CRITICAL','HIGH') else 0)
"
```

## 9. Runtime drift monitoring

```bash
# Take baseline at deploy time
runtime-baseline baseline --container app --runtime crictl --output baseline.json

# Continuous monitor in CI/daemon
runtime-baseline monitor --container app --baseline baseline.json --interval 30 --output drift-findings.json
```

## Safety rules

1. Never run escape PoCs against production or shared infrastructure
2. Keep lab VMs off any network with real workloads
3. Snapshot the VM before destructive tests
4. Use only your own images/registry; never pull untrusted images into the lab
5. Log all activities for audit (lab is for research, keep records)
