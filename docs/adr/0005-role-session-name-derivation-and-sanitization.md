# ADR-0005: AWS_ROLE_SESSION_NAME derivation and sanitization

- **Status:** accepted
- **Date:** 2026-01-02

> Backfilled from #11 ("handle empty pod names", 2025-06-19) and #29 ("sanitize AWS_ROLE_SESSION_NAME", 2026-01-02), which together settled the contract.

## Context

The injected env includes `AWS_ROLE_SESSION_NAME`, which surfaces in CloudTrail and STS audit logs. Two problems made a naive `pod.Name` wrong:

- Pods created by controllers (Deployments, Jobs) have **no `.Name` at admission time** — only `generateName`. Using `pod.Name` yielded empty session names (#11).
- AWS STS restricts session names to `[A-Za-z0-9+=,.@_-]` and caps length at 64; Kubernetes names and namespaces can contain characters STS rejects (#29).

## Decision

Derive the session name via a fallback chain in `generateRoleSessionName`: `pod.Name` → `generateName` + `UnixNano` → `namespace-serviceaccount` → `namespace-pod`. Then `sanitizeSessionName` maps any out-of-charset byte to `-`, and the result is truncated to 64 characters.

## Consequences

- Every injected pod gets a valid, non-empty session name, including controller-created pods before their name is assigned.
- The `UnixNano` suffix gives uniqueness when many pods share a `generateName` in the same second.
- Sanitization is **lossy** — distinct source names can collide after invalid characters collapse to `-`. Accepted: session names are for traceability, not identity.

## Alternatives Considered

- **Leave `AWS_ROLE_SESSION_NAME` unset** — the SDK auto-generates one, but it's opaque and useless for correlating activity back to a pod.
- **Use the pod UID** — unique and always present, but meaningless in CloudTrail.
- **Require a pod name** — would reject controller-created pods, breaking the common case.
