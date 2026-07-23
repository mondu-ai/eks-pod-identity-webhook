# ADR-0002: Helm chart lives in a dedicated repo

- **Status:** accepted
- **Date:** 2025-06-06

> Backfilled from #10 ("relocate Helm chart to a dedicated repo"). The chart was originally added in-repo (#4) and moved out the next day.

## Context

The Helm chart shipped inside this repository at first. That tied every chart tweak to an app release, forced chart-only changes through the app's CI, and didn't fit how the org publishes charts — a single community index (`mondu-ai/helm-charts-community`, served via GitHub Pages) that users `helm repo add`.

## Decision

Move the chart out to `mondu-ai/helm-charts-community`. This repo ships only the Go binary and the container image (`ghcr.io`). The chart owns the Deployment, RBAC, Service, MutatingWebhookConfiguration, and TLS wiring.

## Consequences

- Chart and app version and release independently.
- The Deployment's **RBAC lives in the chart repo**, so a change here that needs new Kubernetes permissions (e.g. a new API call beyond the ServiceAccount `Get`) requires a coordinated PR over there — this is the single most important cross-repo coupling to remember.
- E2E tests can't use an in-repo chart; they pull the *published* one (see ADR-0003), which means e2e validates the real chart contract but is tied to whatever version is published.
- Contributors touching install/deploy behavior have to know to look in a second repo.

## Alternatives Considered

- **Keep the chart in-repo** — simplest for a single consumer, but couples releases and diverges from the org's chart-index convention.
- **Raw manifests / kustomize only** — no `helm repo add` UX; the local `tmp/manifests/` remain only as a dev-time reference.
