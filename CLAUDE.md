# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Kubernetes **mutating admission webhook** that gives pods in *non-EKS* clusters (GKE, AKS, on-prem — anything with an OIDC issuer) the same AWS IRSA experience as EKS. When a pod's ServiceAccount carries the `eks.amazonaws.com/role-arn` annotation, the webhook injects a projected SA token volume, its mount, and the AWS SDK env vars so the SDK can `AssumeRoleWithWebIdentity`. mondu-ai fork; distributed as a `ghcr.io` container and installed via the Helm chart in a **separate repo** (`mondu-ai/helm-charts-community`).

## Commands

```bash
make test           # unit tests (root module only, -race -timeout=30s)
make lint           # installs golangci-lint v2.12.2 (pinned) and runs it
make ci             # deps fmt vet lint security test — mirrors PR CI
make test-coverage  # writes coverage.out + coverage.html
make security       # gosec → results.sarif (medium severity/confidence)
make e2e            # builds docker image, spins up Kind, runs e2e module
make e2e-retain     # same, but keeps the cluster for debugging
make e2e-clean      # kind delete cluster --name eks-webhook-e2e
```

Run a single unit test (root is a single `package main`):

```bash
go test -race -run 'TestGenerateRoleSessionName$' -v .
```

## Architecture

Everything runs from one file, `main.go` (`package main`). There is no `internal/` or `pkg/`. Flow of a request:

`handleMutatePod` → `parseAdmissionReview` → `processAdmissionRequest` → `createMutationResponse` → `createPatch` → the `create*Patches` helpers, which emit **JSON Patch** ops.

Load-bearing behavior to keep in mind before changing anything:

- **The webhook calls the k8s API mid-admission.** `getRoleArnFromServiceAccount` does a live `ServiceAccounts().Get()` to read the `role-arn` annotation off the SA (the annotation is on the *ServiceAccount*, not the pod). This is why the deployment needs RBAC `get` on serviceaccounts — a behavior change here can require a matching RBAC change in the Helm chart repo.
- **Fail semantics are asymmetric.** Non-pod resources are *allowed unmutated* (fail-open). But a pod that fails to deserialize, or a patch that fails to build, is *denied* (`Allowed=false`). Preserve this split.
- **Injection is idempotent.** Every `create*Patches` helper checks for an existing volume / mount / env var by name and skips it rather than duplicating or overwriting. Env vars already set by the user are never clobbered.
- **All containers + init containers** get the mount and env vars; the token volume is added once at the pod level.
- **Session-name generation** (`generateRoleSessionName`) has a fallback chain: pod name → `generateName`+UnixNano → `namespace-serviceaccount` → `namespace-pod`, then sanitized to the AWS STS charset `[A-Za-z0-9+=,.@_-]` and truncated to 64 chars. Pods created by controllers often have no `.Name` yet at admission time — that's what the chain handles.
- **TLS certs hot-reload** via controller-runtime `certwatcher` wired into `tls.Config.GetCertificate`; the watcher goroutine is started in `startServer`. Rotating the cert secret must *not* require a pod restart (there's an e2e test asserting this).
- HTTP layer is **Gin** (`/mutate` POST, `/healthz` GET) over TLS on `:8443`. Kube config resolves from `KUBECONFIG` if set, else in-cluster.

Config comes from flags (`-tls-cert-path`, `-tls-key-path`, `-listen-addr`, `-aws-region`) plus env (`LOG_LEVEL=debug` toggles debug logs, `ENV`, `AWS_REGION`). Logging is hand-rolled leveled loggers (`logInfo`/`logWarn`/`logError`/`logDebug`), not a structured logger.

## Two Go modules — this trips people up

- **Root module** `eks-iam-pod-identity-webhook` (go 1.26) — the webhook + `main_test.go`.
- **`e2e/` module** `eks-pod-identity-webhook-e2e` (go 1.24) — a *separate* module.

Consequences: `go test ./...`, `make lint`, `vet`, and `security` from the root **do not touch `e2e/`** (it's excluded in the Makefile and `.golangci.yml`). To work on e2e, `cd e2e` first.

The e2e suite (`e2e/framework/`) creates a Kind cluster, builds the local Docker image tagged `eks-pod-identity-webhook:e2e-test`, and installs the webhook using the **published Helm chart** pulled from `https://mondu-ai.github.io/helm-charts-community` with `image.pullPolicy=Never` + `certManager.enabled=false`. So e2e exercises the real chart, not local manifests — a breaking change to the injected shape may need a coordinated change in the chart repo. All e2e tests share one cluster via `TestMain`; you can't run a single e2e test without that setup path running first. `make e2e` requires Docker.

## Conventions

- Go version lives in go.mod (1.26), the Dockerfile builder (`golang:1.26-alpine`), and CI (`setup-go` → 1.26). Keep those three aligned when bumping.
- `golangci-lint` v2 with strict `funlen` (100 lines / 50 statements) and `cyclop`/`gocyclo` (complexity 15). This is *why* `main.go` is decomposed into many small methods — new code must stay under those limits rather than growing a handler.
- Runtime image is `FROM scratch`, non-root `65534`. The build is `CGO_ENABLED=0` static; a Go builder bump changes the stdlib linked into the final binary (crypto/tls, net/http), so it is not "builder-stage-only".

## Releases

CI (`ci.yml` → `docker` job) publishes images to `ghcr.io/mondu-ai/eks-pod-identity-webhook`:

- **Push to `main`/`develop`** → `sha-<short>` and `<branch>` tags only. Dev images, not a release.
- **Push a `v*` tag** → semver tags (`X.Y.Z`, `X.Y`, `X`) plus `latest` (`latest` is skipped for pre-releases — versions containing `-`). This is the only path to a versioned/`latest` image.

No `v*` tag = no versioned release. The workflow only pushes images — there is no GitHub Release object and no CHANGELOG.

## Architecture Docs

Read these in order before making changes:

1. `README.md` — what the webhook is, how to install it
2. `ARCHITECTURE.md` — runtime shape, request lifecycle, the IRSA injection contract, invariants
3. `docs/coding-style.md` — enforced linter limits and the conventions behind the flat layout
4. `docs/adr/` — architectural decision records (start at `README.md`)

Keep these docs accurate: the IRSA injection contract and the fail-open/fail-closed semantics are load-bearing invariants, not incidental. After an implementation cycle that touches the mutation path, config surface, endpoints, or the module boundary, run `/pilat:arch-sync` to detect and reconcile drift.
