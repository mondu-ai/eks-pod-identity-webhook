# Architecture

A Kubernetes **mutating admission webhook** that brings EKS-style IRSA (IAM Roles for Service Accounts) to *non-EKS* clusters — GKE, AKS, on-prem, anything with an OIDC issuer. When a pod's ServiceAccount carries the `eks.amazonaws.com/role-arn` annotation, the webhook injects a projected ServiceAccount token and the AWS SDK env vars so the SDK can `AssumeRoleWithWebIdentity` against AWS STS — no static credentials.

One thing ships: a static Go binary in a `scratch` container (`ghcr.io`), deployed via the Helm chart in a **separate repo** (`mondu-ai/helm-charts-community`).

## Runtime shape

- **HTTP layer:** Gin, TLS-only, listening on `:8443`.
  - `POST /mutate` — the admission entry point (`handleMutatePod`).
  - `GET /healthz` — liveness/readiness (`handleHealthz`).
- **Kube client:** in-cluster config by default; `KUBECONFIG` env overrides for local runs.
- **TLS:** certificate is served through controller-runtime `certwatcher`, wired into `tls.Config.GetCertificate`. Cert rotation is picked up live — **no pod restart** on secret rotation.
- **Shutdown:** SIGINT/SIGTERM trigger a 5s graceful `server.Shutdown`; the certwatcher goroutine is cancelled via context.

## Request lifecycle

A single `/mutate` request walks this chain (all in `main.go`):

```
handleMutatePod
  → parseAdmissionReview        decode AdmissionReview, reject nil request
  → processAdmissionRequest
      → isValidPodResource      non-pod → ALLOW unmutated (fail-open)
      → deserializePod          decode failure → DENY (fail-closed)
      → createMutationResponse
          → createPatch
              → getRoleArnFromServiceAccount   ← live k8s API call
              → createVolumePatches            pod-level token volume
              → createContainerPatches
                  → addMutationsToContainers   init + main containers
                      → createVolumeMountPatches
                      → createEnvironmentPatches
```

The output is a **JSON Patch** (`[]JSONPatchEntry`) attached to the `AdmissionResponse`. Empty patch → response says "no mutation needed" but still allows.

## The injection contract (hard invariant)

The webhook exists to be **wire-compatible with EKS IRSA**. These constants are load-bearing — the AWS SDK and the OIDC trust policy on the AWS side expect exactly these values. Changing any of them breaks credential resolution for every consumer and **counts as drift**, not refactoring.

| Concern | Value | Source of truth |
|---|---|---|
| SA annotation read | `eks.amazonaws.com/role-arn` | `awsRoleArnAnnotationKey` |
| Token audience | `sts.amazonaws.com` | `projectedTokenAudience` |
| Token mount path | `/var/run/secrets/eks.amazonaws.com/serviceaccount` | `awsTokenMountPath` |
| Token expiry | 3600s | `projectedTokenExpiration` |
| Injected env | `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN`, `AWS_REGION`, `AWS_DEFAULT_REGION`, `AWS_ROLE_SESSION_NAME` | const block, top of `main.go` |

`AWS_ROLE_SESSION_NAME` is derived by `generateRoleSessionName`: pod name → `generateName`+UnixNano → `namespace-serviceaccount` → `namespace-pod`, then `sanitizeSessionName` restricts it to the AWS STS charset `[A-Za-z0-9+=,.@_-]` and truncates to 64 chars. The fallback chain exists because controller-created pods often have no `.Name` at admission time.

## Behavioral invariants

These are not incidental — preserve them across changes:

- **Asymmetric fail semantics.** Non-pod resources are *allowed unmutated*. A pod that fails to deserialize, or whose patch fails to build, is *denied* (`Allowed: false`). Don't flatten this into "always allow" or "always deny".
- **Idempotency.** Every `create*Patches` helper checks for the volume / mount / env var *by name* before adding it. A user-set env var is never overwritten; a re-admitted pod isn't double-patched.
- **Injection reaches all containers.** Both `initContainers` and `containers` get the mount + env vars; the token volume is added once at pod level.
- **RBAC coupling.** `getRoleArnFromServiceAccount` does a live `ServiceAccounts().Get()` — the annotation lives on the *ServiceAccount*, not the pod. The deployment therefore needs RBAC `get` on `serviceaccounts`. That RBAC lives in the **chart repo**, so adding new API calls here requires a coordinated change there.

## Code layout

The service is a single flat `package main` — there is no `internal/` or `pkg/`, and that's deliberate (see the linter limits in `docs/coding-style.md`; small composable functions, not layered packages). `main.go` is organized in bands: constants → package vars/loggers → `Config`/`WebhookServer`/`JSONPatchEntry` types → `main` and setup (`parseConfig`, `setupKubernetesConfig`, `setupRouter`, `createHTTPServer`, `startServer`) → the handler/patch methods.

Two **separate Go modules** live here:

- **Root** — `eks-iam-pod-identity-webhook` (go 1.26): the webhook + `main_test.go` (unit tests, table-driven, testify).
- **`e2e/`** — `eks-pod-identity-webhook-e2e` (go 1.24): a standalone module. `TestMain` provisions a Kind cluster, builds the local image as `eks-pod-identity-webhook:e2e-test`, and installs the webhook using the **published Helm chart** (`pullPolicy=Never`, `certManager.enabled=false`). It exercises the real chart contract, not local manifests. `e2e/framework/` holds the cluster/helm/cert/pod-builder helpers.

`go test ./...`, `make lint`, `vet`, and `security` from the root **do not touch `e2e/`** — it's a different module, explicitly excluded in the Makefile and `.golangci.yml`.

## External boundaries

- **Kubernetes API server** — inbound admission calls; outbound `ServiceAccounts().Get()`.
- **Helm chart** (`mondu-ai/helm-charts-community`) — owns Deployment, RBAC, Service, MutatingWebhookConfiguration, TLS wiring. Not in this repo.
- **Container registry** (`ghcr.io/mondu-ai/eks-pod-identity-webhook`) — CI builds multi-arch (amd64/arm64) images on push/tag.
- **AWS STS** — not called by the webhook; the *injected pod* calls it at runtime using the projected token.

## Keeping This Document Accurate

This project is a single flat package, so drift shows up in specific, greppable places. After implementation changes, verify:

- **Injection contract table** matches the const block at the top of `main.go`. Check the values directly:
  `grep -nE 'awsRoleArnAnnotationKey|projectedTokenAudience|awsTokenMountPath|projectedTokenExpiration|awsWebIdentityTokenFileEnv|awsRoleArnEnv|awsRegionEnv|awsDefaultRegionEnv|awsRoleSessionNameEnv' main.go`
  Any changed value is either a documented, intentional break of EKS compatibility (rare — update this doc *and* flag it loudly) or a bug.
- **Endpoints** in the "Runtime shape" section match `setupRouter`:
  `grep -nE 'router\.(POST|GET)' main.go`
- **Config surface** matches `parseConfig`:
  `grep -n 'flag\.StringVar' main.go`
- **Request-lifecycle chain** still reflects the real call graph — if handlers/helpers are renamed, split, or reordered, update the diagram.
- **RBAC coupling** — if a new k8s API call is added (anything beyond the SA `Get`), note it here and confirm the chart repo's RBAC grants it.
- **Module boundary** — if `e2e/`'s Kind/Helm flow changes (new `--set` flags, different chart source), update the "Code layout" and boundaries sections. Chart `--set` flags live in `e2e/framework/helm.go`.
- **Go version** stays aligned across `go.mod`, the Dockerfile builder, and CI (`setup-go`).

Run `/pilat:arch-sync` to check automatically.
