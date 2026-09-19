---
id: CE-012
name: Workload identity token theft
category: cloud/identity
mitre_attack: [T1528, T1550.001, T1078.004]
risk: high
detection_rules: [SIGMA-013, FALCO-010]
---

# CE-012 — Workload identity token theft

## Summary

The token-based counterpart to CE-011. Workloads that federate to cloud
identity without long-lived keys (IRSA on EKS, GKE Workload Identity, Azure
Workload Identity on AKS) receive a *projected* service-account token in the pod
filesystem, plus environment variables that point at it. The token is a signed
JWT addressed to a cloud audience: whoever holds it can exchange it at the
provider's token/STS endpoint for cloud credentials — often from outside the
cluster, for as long as the token's `exp` allows. A container that can read the
file has the workload's cloud identity; unlike CE-011 there is no link-local
address to block, only a file permission and a token audience.

## Prerequisites

- Read access to the projected token file or the env var pointing at it
- The pod's service account bound to a cloud role (IRSA, workload identity
  binding, federated credential)
- Egress to the cloud token/STS endpoint (from inside the pod, or from the
  operator's host once the token has been exfiltrated)
- For the out-of-cluster variant: the cluster's OIDC issuer must be publicly
  reachable — the common default for managed control planes

## Attack path

1. Locate the token: the default service-account path, the provider-specific
   projected paths, and any env var naming a token file
2. Read the JWT and decode its claims without a key — `aud`, `sub`, `exp`, and
   the issuer say exactly which cloud identity it maps to and how long it lasts
3. Exchange the token for cloud credentials at the provider's token/STS endpoint
   (`AssumeRoleWithWebIdentity`-style), either from the pod or from the
   operator's host after exfiltration
4. Note the constraints before relying on it: audience mismatch kills the
   exchange; short `expirationSeconds` bounds the window; the kubelet rotates
   the projected file, so re-reading keeps the stolen identity fresh until the
   pod is deleted or the binding is removed
5. Pivot with the cloud identity — the interesting targets are the same as
   CE-011: object storage, secrets managers, the container registry, and the
   cluster's own control plane if the role reaches it

## PoC sketch

```bash
# default projected token and provider-specific projections
ls -l /var/run/secrets/kubernetes.io/serviceaccount/token
ls -l /var/run/secrets/eks.amazonaws.com/serviceaccount/ 2>/dev/null
ls -l /var/run/secrets/azure/tokens/ 2>/dev/null
ls -l /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null

# env vars that name a federated token file / role to assume
env | grep -E 'AWS_(WEB_IDENTITY_TOKEN_FILE|ROLE_ARN)|AZURE_(FEDERATED_TOKEN_FILE|CLIENT_ID)|GOOGLE'

# the token is signed, not encrypted: claims are readable with no key
cut -d. -f2 /var/run/secrets/kubernetes.io/serviceaccount/token \
  | base64 -d 2>/dev/null | jq '{iss, aud, sub, exp}'
```

The JWT signature means the token cannot be *forged* by the container — it can
only be stolen and replayed. The exchange step against the provider's endpoint is
deliberately left as a mechanics description rather than a command: it is the
part this corpus will not hand over as a one-liner (see `SECURITY.md`).

## Detection

- **Sigma:** `SIGMA-013` — processes reading projected workload-identity token
  paths or referencing the federated-token environment variables
- **Falco:** `FALCO-010` — opens/reads of projected token paths from inside a
  container by a process that is not the workload's own runtime
- **Kubernetes audit:** `TokenRequest` for unexpected audiences
  (`serviceaccounts/token` create) and projected-volume token issuance are
  visible at the API server; plain file reads are *not* audited by default —
  this technique's runtime footprint is small by design
- **Cloud:** `AssumeRoleWithWebIdentity` / Workload Identity token exchanges
  from IPs outside the cluster's egress range, unfamiliar `RoleSessionName`
  values, and first-seen role/user-agent pairs
- **Admission:** `admission-review` — flag `automountServiceAccountToken: true`
  on pods that never call the API server, and projected volumes requesting
  audiences wider than the workload needs

## Mitigation

- Short projected-token lifetimes (`expirationSeconds`) — bounds replay to a
  small window instead of the token's default hour
- Audience-scoped projections: one audience per workload, matching exactly the
  cloud role it may exchange for
- `automountServiceAccountToken: false` on pods that do not need API access;
  mount only the specific projected volume required
- Cloud-side condition keys on the trust policy (`sub`, `aud`, source IP) so a
  stolen token cannot be exchanged from arbitrary networks
- Never place token paths in world-readable locations or bake tokens into
  images, args, logs, or crash dumps
- Alert on token-file reads by shells, `env`, `tar`, and backup tooling — those
  are the reads that legitimately never happen in these pods

## References

- AWS IAM Roles for Service Accounts (IRSA) documentation
- Azure Workload Identity documentation
- MITRE ATT&CK T1528 (Steal Application Access Token), T1550.001 (Use Alternate
  Authentication Material: Application Access Token)
