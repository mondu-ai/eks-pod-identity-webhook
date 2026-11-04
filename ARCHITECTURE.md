# Architecture

A Kubernetes **mutating admission webhook** that brings EKS-style IRSA (IAM Roles for Service Accounts) to *non-EKS* clusters — GKE, AKS, on-prem, anything with an OIDC issuer. When a pod's ServiceAccount carries the `eks.amazonaws.com/role-arn` annotation, the webhook injects a projected ServiceAccount token and the AWS SDK env vars so the SDK can `AssumeRoleWithWebIdentity` against AWS STS — no static credentials.

One thing ships: a static Go binary in a `scratch` container (`ghcr.io`), deployed via the Helm chart in a **separate repo** (`mondu-ai/helm-charts-community`).

## Runtime shape

- **HTTP layer:** Gin, TLS-only, **HTTP/1.1 only** (`TLSNextProto` is empty), listening on `:8443`.
  - `POST /mutate` — the admission entry point (`handleMutatePod`).
  - `GET /healthz` — liveness/readiness (`handleHealthz`).
- **Kube client:** in-cluster config by default; `KUBECONFIG` env overrides for local runs. Client-side rate limiting is off (`QPS = -1`), as in kube-apiserver's own webhook client.
- **TLS:** certificate is served through controller-runtime `certwatcher`, wired into `tls.Config.GetCertificate`. Cert rotation is picked up live — **no pod restart** on secret rotation.
- **Shutdown:** the first SIGINT/SIGTERM starts a **drain** (`drain`): every response carries `Connection: close` (`closeWhileDraining`), for at least `shutdownDrainDelay` (10s, while the replica leaves the Service endpoints) and then until clients have closed every connection, counted through `http.Server.ConnState` (`trackConnState`), capped at the drain timeout from `SHUTDOWN_DRAIN_TIMEOUT` (default 20s; the chart sets 100s). Only then a 5s `server.Shutdown`; the certwatcher goroutine is cancelled via context. A second signal ends the process at once. See ADR-0007.

## Request lifecycle

A single `/mutate` request walks this chain (all in `main.go`):

```
handleMutatePod
  → parseAdmissionReview        decode AdmissionReview, reject nil request
  → processAdmissionRequest
      → isValidPodResource      non-pod → ALLOW unmutated (fail-open)
      → request.Operation       anything but CREATE → ALLOW unmutated, no SA lookup
      → deserializePod          decode failure → DENY 500 (fail-closed)
      → createMutationResponse  SA lookup failure → DENY 503 + Retry-After (retryableDenial)
          → createPatch         patch build failure → DENY 500
              → getRoleArnFromServiceAccount   ← live k8s API call, 3s timeout
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

- **Asymmetric fail semantics.** Non-pod resources are *allowed unmutated*. A pod that fails to deserialize, or whose patch fails to build, is *denied* (`Allowed: false`, 500). Don't flatten this into "always allow" or "always deny".
- **An unknown role denies for a retry, never admits.** When the ServiceAccount lookup fails (`errServiceAccountLookup`), the pod is denied with 503 `ServiceUnavailable` and `Details.RetryAfterSeconds`; kube-apiserver turns that into `Retry-After`, which clients built on client-go, the built-in controllers among them, retry. Admitting it unmutated would start a pod without AWS credentials. The lookup has its own 3s timeout so the webhook decides before the apiserver's webhook timeout — past it, the chart's `failurePolicy: Ignore` admits the pod unmutated. See ADR-0006.
- **Only CREATE is mutated.** A pod's volumes and env are immutable after creation; a patch on UPDATE gets the whole update rejected by the apiserver.
- **The client closes idle connections, never the server.** kube-apiserver reuses idle HTTP/1.1 keep-alive connections to webhooks for 90s (`http.DefaultTransport.IdleConnTimeout`); a server-side close of one it is about to reuse fails the call, and `failurePolicy: Ignore` then admits the pod unmutated. Hence `idleTimeout` (120s) must stay above 90s, and the drain waits for clients instead of closing idle connections. The chart's `terminationGracePeriodSeconds` must cover the drain timeout plus the 5s shutdown: the defaults (20s + 5s) fit Kubernetes' default 30s, and the chart sets 100s with a 120s grace period.
- **Idempotency.** Every `create*Patches` helper checks for the volume / mount / env var *by name* before adding it. A user-set env var is never overwritten; a re-admitted pod isn't double-patched.
- **Injection reaches all containers.** Both `initContainers` and `containers` get the mount + env vars; the token volume is added once at pod level.
- **RBAC coupling.** `getRoleArnFromServiceAccount` does a live `ServiceAccounts().Get()` — the annotation lives on the *ServiceAccount*, not the pod. The deployment therefore needs RBAC `get` on `serviceaccounts`. That RBAC lives in the **chart repo**, so adding new API calls here requires a coordinated change there.

## Code layout

The service is a single flat `package main` — there is no `internal/` or `pkg/`, and that's deliberate (see the linter limits in `docs/coding-style.md`; small composable functions, not layered packages). `main.go` is organized in bands: constants → package vars/loggers → `Config`/`WebhookServer`/`JSONPatchEntry` types → `main` and setup (`parseConfig`, `setupKubernetesConfig`, `setupRouter`, `createHTTPServer`, `startServer`) → the handler/patch methods.

Two **separate Go modules** live here:

- **Root** — `eks-iam-pod-identity-webhook` (go 1.26): the webhook + `main_test.go` (unit tests, table-driven, testify).
- **`e2e/`** — `eks-pod-identity-webhook-e2e` (go 1.24): a standalone module. `TestMain` provisions a Kind cluster, builds the local image as `eks-pod-identity-webhook:e2e-test`, and installs the webhook using the **published Helm chart** (`pullPolicy=Never`, `certManager.enabled=false`), then patches the Deployment with the chart's drain settings (`SHUTDOWN_DRAIN_TIMEOUT=100s`, `terminationGracePeriodSeconds: 120`) until the published chart sets them. It exercises the real chart contract, not local manifests. `e2e/framework/` holds the cluster/helm/cert/pod-builder helpers plus webhook restarts (`rollout.go`) and RBAC revocation (`rbac.go`). Load tests (burst, rollout) admit pods by dry-run through `burstClientset`, which has no client-side rate limit, so the load actually reaches the webhook.

`go test ./...`, `make lint`, `vet`, and `security` from the root **do not touch `e2e/`** — it's a different module, explicitly excluded in the Makefile and `.golangci.yml`. CI runs it separately via the reusable `.github/workflows/e2e.yml`, on every PR and before every image push.

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
- **Config surface** matches `parseConfig` (flags plus `SHUTDOWN_DRAIN_TIMEOUT`):
  `grep -nE 'flag\.StringVar|Getenv' main.go`
- **Request-lifecycle chain** still reflects the real call graph — if handlers/helpers are renamed, split, or reordered, update the diagram.
- **RBAC coupling** — if a new k8s API call is added (anything beyond the SA `Get`), note it here and confirm the chart repo's RBAC grants it.
- **Module boundary** — if `e2e/`'s Kind/Helm flow changes (new `--set` flags, different chart source, post-install patches), update the "Code layout" and boundaries sections. Chart `--set` flags live in `e2e/framework/helm.go`; the grace-period patch in `e2e/framework/rollout.go` goes once the published chart sets it.
- **Connection lifecycle** — `idleTimeout` stays above kube-apiserver's 90s keep-alive, and the default drain timeout plus `shutdownTimeout` fits Kubernetes' default 30s grace period, and the chart's `terminationGracePeriodSeconds` covers its own `shutdownDrainTimeout` plus 5s:
  `grep -nE 'idleTimeout|ShutdownDrain|shutdownTimeout' main.go`
- **Go version** stays aligned across `go.mod`, the Dockerfile builder, and CI (`setup-go`).

Run `/pilat:arch-sync` to check automatically.
