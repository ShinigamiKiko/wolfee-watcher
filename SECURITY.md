# Security Policy

## Reporting a vulnerability

Please report security issues privately — **do not open a public issue or PR.**

- Preferred: open a [private security advisory](../../security/advisories/new)
  on this repository.
- Or email: `<security contact email>`.

Include the affected component, a description, and reproduction steps or a PoC
if you have one. We aim to acknowledge within a few working days.

Please give us reasonable time to release a fix before any public disclosure.

## Scope

This is a runtime-security platform for Kubernetes; the trust model matters when
assessing reports:

- **Service-to-service traffic is mTLS** (TLS 1.3, CA-verified client certs
  issued by `cert-server`). Identity is the certificate CommonName.
- **The `kvisior` gateway** authenticates UI users and sets the trusted
  `X-Acting-User` / `X-Acting-Role` headers; backends trust those only because
  they are reachable exclusively over mTLS from the gateway.
- **`/internal/push/*`** endpoints are authenticated with the shared
  `INTERNAL_PUSH_SECRET`; an unset secret fails closed.
- **`tracee-bridge:8080`** ingests Tracee events over plain HTTP by design
  (Tracee is a third-party hostNetwork DaemonSet that cannot present a client
  cert). It is protected at the network layer via `networkPolicy.nodeCIDRs`.
  Reports about this path should account for that boundary.

## Supported versions

Security fixes target the latest release / `main`.
