# ADR-0003: E2E tests via a separate module, Kind, and the published chart

- **Status:** accepted
- **Date:** 2026-01-02

> Backfilled from #30 ("add e2e tests with kind").

## Context

The unit tests in `main_test.go` cover patch construction well, but they mock the Kubernetes client and never exercise the real admission wiring: TLS handshake with the API server, RBAC, the MutatingWebhookConfiguration, and the Helm chart that assembles all of it. A bug in any of those is invisible to unit tests. Since the chart now lives in a separate repo (ADR-0002), chart/app drift is a real failure mode with no in-repo signal.

## Decision

Add end-to-end tests as a **separate Go module** under `e2e/`. `TestMain` builds the local image as `eks-pod-identity-webhook:e2e-test`, provisions a Kind cluster, and installs the webhook using the **published Helm chart** with `image.pullPolicy=Never` and `certManager.enabled=false`.

## Consequences

- E2E exercises the real chart contract against a real API server — it catches chart/app drift the unit tests can't.
- Heavy test-only dependencies (`sigs.k8s.io/kind`, etc.) stay out of the app's `go.mod`, and `e2e/` is excluded from the root's lint/vet/security/`go test ./...` — so `cd e2e` is required to work on it.
- Requires Docker, and the whole suite shares one cluster via `TestMain`; a single e2e test can't run without the cluster bootstrap.
- The suite is tied to whatever chart version is currently published upstream.

## Alternatives Considered

- **envtest / controller-runtime test env** — fast, but no real chart, no real MutatingWebhookConfiguration wiring; wouldn't catch chart drift.
- **Test against local `tmp/manifests/`** — validates manifests we don't actually ship, not the chart users install.
- **Single module with build tags** — pollutes the app's dependency graph with test-only k8s tooling.
