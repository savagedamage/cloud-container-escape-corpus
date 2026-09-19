#!/usr/bin/env bash
# Idempotent bring-up for the container-escape lab.
#
# Creates the kind cluster if absent, ensures the `vulnerable` and `secure`
# namespaces carry the right PodSecurity labels, and applies every lab pod
# manifest in this directory. Safe to re-run: every step is a no-op when the
# target state already exists.
#
# FOR ISOLATED LAB USE ONLY. Everything this script deploys is deliberately
# vulnerable — never run it against a shared or production cluster.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_NAME="${LAB_CLUSTER_NAME:-escape-lab}"
KIND_WAIT="${LAB_KIND_WAIT:-120s}"

log() { printf '[lab-up] %s\n' "$*"; }
warn() { printf '[lab-up] WARN: %s\n' "$*" >&2; }
die() { printf '[lab-up] ERROR: %s\n' "$*" >&2; exit 1; }

# --- docker access -----------------------------------------------------------
# A fresh login shell may not yet be in the docker group. If docker is not
# usable, try one re-exec through `sg docker` (no-op loop guard), otherwise
# tell the operator to re-enter the group.
if ! docker info >/dev/null 2>&1; then
    if [[ "${LAB_UP_REEXEC:-0}" != "1" ]] && command -v sg >/dev/null 2>&1; then
        log "docker not accessible in this shell; re-executing under the docker group"
        export LAB_UP_REEXEC=1
        exec sg docker -c "LAB_UP_REEXEC=1 bash $(printf '%q' "${BASH_SOURCE[0]}")"
    fi
    die "docker daemon not reachable. Run 'newgrp docker' first, then re-run this script."
fi

for bin in docker kind kubectl; do
    command -v "$bin" >/dev/null 2>&1 || die "required command not found: $bin"
done

# --- kind cluster ------------------------------------------------------------
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    log "kind cluster '$CLUSTER_NAME' already exists - reusing"
else
    log "creating kind cluster '$CLUSTER_NAME'"
    kind_config="$(mktemp)"
    trap 'rm -f "$kind_config"' EXIT
    cat >"$kind_config" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
EOF
    kind create cluster --name "$CLUSTER_NAME" --config "$kind_config" --wait "$KIND_WAIT"
    rm -f "$kind_config"
    trap - EXIT
fi

context="kind-$CLUSTER_NAME"
if kubectl config get-contexts -o name 2>/dev/null | grep -qx "$context"; then
    kubectl config use-context "$context" >/dev/null
else
    warn "kubeconfig context '$context' not found; using current context"
fi
kubectl cluster-info >/dev/null 2>&1 || die "cluster '$CLUSTER_NAME' is not reachable via kubectl"

# --- namespaces --------------------------------------------------------------
# vulnerable: PodSecurity=privileged (escape fixtures are admitted here)
# secure:     PodSecurity=restricted (control namespace for comparison)
ensure_namespace() {
    local ns="$1"
    shift
    if kubectl get namespace "$ns" >/dev/null 2>&1; then
        log "namespace '$ns' already exists - ensuring labels"
    else
        log "creating namespace '$ns'"
        kubectl create namespace "$ns" >/dev/null
    fi
    kubectl label namespace "$ns" "$@" --overwrite
}

ensure_namespace vulnerable \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/audit=privileged \
    pod-security.kubernetes.io/warn=privileged

ensure_namespace secure \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/audit=restricted \
    pod-security.kubernetes.io/warn=restricted

# --- lab manifests -----------------------------------------------------------
shopt -s nullglob
manifests=("$LAB_DIR"/*-pod.yaml)
shopt -u nullglob

if ((${#manifests[@]} == 0)); then
    die "no pod manifests found in $LAB_DIR"
fi

log "applying ${#manifests[@]} lab manifest(s)"
for manifest in "${manifests[@]}"; do
    kubectl apply -f "$manifest"
done

log "lab bring-up complete; pods in 'vulnerable':"
kubectl get pods -n vulnerable -o wide || true
log "next: ./corpus/lab/verify.sh"
