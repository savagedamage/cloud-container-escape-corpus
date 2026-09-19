---
id: CE-011
name: IMDS instance metadata credential theft
category: cloud/metadata
mitre_attack: [T1552.005, T1078.004, T1530]
risk: critical
detection_rules: [SIGMA-012, FALCO-009]
---

# CE-011 — IMDS instance metadata credential theft

## Summary

The cloud half of the escape problem. A workload that can reach the link-local
instance metadata service (`169.254.169.254`, `fd00:ec2::254` over IPv6) can read
the instance's IAM role credentials, user data, and network layout. IMDSv1 is an
unauthenticated GET; IMDSv2 requires a session token first, but the token
endpoint sits on the same address and is reachable from the same workload paths.
Node instance profiles are usually cluster-wide, so one compromised container
frequently yields the cloud identity of every node in the pool.

## Prerequisites

- Egress from the container to the metadata address (no NetworkPolicy metadata
  block, no proxy-only egress)
- IMDSv1 enabled (no token required) or IMDSv2 with a reachable token endpoint
- A cloud role attached to the node/instance with any usable permissions
- Metadata reachable from the pod network — `hostNetwork` pods, IMDS hop limit
  above 1, or a CNI that does not filter link-local

## Attack path

1. Probe the metadata endpoint with a short timeout — blocked means a silent hang
2. Read the role name from `/latest/meta-data/iam/security-credentials/`
3. Read the credential document for that role (AccessKeyId / SecretAccessKey /
   Token; on Azure/GCP equivalents the same surface exposes managed-identity and
   service-account tokens)
4. Harvest the rest of the surface: `/latest/user-data` (bootstrap secrets, join
   tokens, kubelet flags), `/latest/meta-data/placement/region` (which control
   plane the identity belongs to)
5. Use the credentials out of band — cloud API calls from the operator's own
   host, not from inside the cluster, so the calls do not appear to originate
   from the pod CIDR
6. No container-side cleanup exists; the credential stays valid until expiry or
   role rotation

## PoC sketch

```bash
# IMDSv1 — unauthenticated read of the role name and its credentials
curl -s -m 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2 — session token first, then the same paths with the token header
TOKEN=$(curl -s -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -m 2 -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# bootstrap material is often worth more than the role itself
curl -s -m 2 http://169.254.169.254/latest/user-data

# which account/region does this identity belong to?
curl -s -m 2 http://169.254.169.254/latest/meta-data/placement/region
```

Note what the metadata service can and cannot tell you: the credential response
includes an expiry timestamp, so a short-lived role is a time-boxed theft, not a
permanent foothold. The exchange of the credential for API access happens
outside the corpus's scope — this is a mechanics sketch, not a turnkey exploit.

## Detection

- **Network:** egress to the metadata address from pod CIDRs; CNI/NetworkPolicy
  audit for namespaces with unfiltered link-local egress. VPC flow logs do not
  capture link-local traffic — do not assume they cover this
- **Sigma:** `SIGMA-012` — metadata URL/role-path access in process command lines
- **Falco:** `FALCO-009` — connect/execve toward the metadata address from a
  container
- **Cloud:** GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`
  and CloudTrail calls made with a node role's credentials from outside the
  cluster's NAT/VPC endpoints
- **Admission:** `admission-review` — flag `hostNetwork` pods and namespaces
  with no egress policy, which are the pods that reach IMDS unfiltered

## Mitigation

- IMDSv2 required (`HttpTokens=required`) with `HttpPutResponseHopLimit=1` — the
  single highest-value control; it removes the unauthenticated read entirely
- Block `169.254.169.254`/`fd00:ec2::254` at the CNI, NetworkPolicy, and egress
  proxy layers so pods have no direct path
- Prefer workload-level identity (IRSA, EKS Pod Identity, GKE Workload Identity,
  Azure Workload Identity) over node instance profiles, so no pod inherits the
  node role — see CE-012
- Scout/bootstrap data in `user-data` should never contain long-lived secrets
- Keep node roles scoped to node duties only; treat node credentials as
  external-facing and alert on their use from unexpected networks

## References

- AWS EC2 instance metadata service documentation
- MITRE ATT&CK T1552.005 (Cloud Instance Metadata API), T1078.004 (Cloud Accounts)
