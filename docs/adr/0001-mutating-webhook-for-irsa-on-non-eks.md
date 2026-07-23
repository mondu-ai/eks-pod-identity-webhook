# ADR-0001: Mutating admission webhook for IRSA on non-EKS clusters

- **Status:** accepted
- **Date:** 2025-06-05

> Backfilled from the initial commit. Records the founding architecture as it stands.

## Context

Pods running outside EKS — GKE, AKS, on-prem — needed to call AWS without static, long-lived credentials. EKS already solves this with IRSA: annotate a ServiceAccount with an IAM role ARN, and the pod gets a projected OIDC token it exchanges with STS for temporary credentials. We wanted that exact developer experience on any cluster with an OIDC issuer, with zero changes to application code or the AWS SDK.

## Decision

Build a **mutating admission webhook** that is wire-compatible with EKS IRSA:

- Read the `eks.amazonaws.com/role-arn` annotation from the pod's **ServiceAccount** (live `Get` at admission time), not from the pod.
- Inject the same projected token volume (`sts.amazonaws.com` audience), mount path, and `AWS_*` env vars EKS uses, so the unmodified AWS SDK resolves credentials identically.
- Ship as a single flat `package main` — no `internal/`/`pkg/` layering — served over TLS via Gin (`POST /mutate`, `GET /healthz`).

## Consequences

- Existing EKS tooling, IAM trust policies, and SDK behavior work unchanged — the injected shape is a hard contract (see `ARCHITECTURE.md`).
- The webhook needs RBAC `get` on `serviceaccounts`, and makes a live API call inside the admission path — coupling webhook latency/availability to the API server.
- Flat package keeps the codebase small and readable but constrains growth; the strict `funlen`/`cyclop` limits (see `docs/coding-style.md`) enforce decomposition into small functions instead of layers.

## Alternatives Considered

- **Use `aws/amazon-eks-pod-identity-webhook` directly** — heavier, EKS-oriented, and harder to bend to our non-EKS deployment and TLS story; a focused reimplementation was simpler to own.
- **Credential sidecar / init container** — requires changing pod specs or app images; less transparent than admission-time injection.
- **Post-hoc controller reconciling pods** — can't mutate the pod before it's scheduled; racy and weaker than an admission gate.
