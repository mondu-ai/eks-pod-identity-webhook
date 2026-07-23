# ADR-0004: TLS certificate hot-reload via certwatcher

- **Status:** accepted
- **Date:** 2026-04-26

> Backfilled from #60 ("TLS certificate hot-reloading via certwatcher").

## Context

The webhook serves TLS on `:8443`, and its serving cert is rotated periodically (cert-manager renewals). With the cert loaded once at startup, a rotation left the process serving a stale certificate until the pod was restarted — a window in which the API server can reject the webhook's cert and, because admission is in the pod-creation path, disrupt scheduling cluster-wide.

## Decision

Serve the certificate through controller-runtime's `certwatcher`, wired into `tls.Config.GetCertificate`. The watcher runs as a goroutine started in `startServer` and is cancelled via context on shutdown; the cert is resolved per-handshake, so a rotated secret is picked up live.

## Consequences

- Certificate rotation requires **no pod restart**; the disruption window is closed.
- Adds a controller-runtime dependency (for `certwatcher` only).
- Certificate resolution moves to per-connection (`GetCertificate`) instead of a static `Certificates` slice.
- An e2e test (`TestCertificateHotReload`) asserts the webhook keeps working across a rotation — this behavior is now covered, not incidental.

## Alternatives Considered

- **Restart the pod on rotation** — disruptive and defeats the point of graceful renewal.
- **Hand-rolled fsnotify watcher** — reinvents `certwatcher`, which already handles the atomic-rename semantics of mounted secret updates.
- **SIGHUP-triggered reload** — needs external orchestration to send the signal; `certwatcher` reacts to the filesystem directly.
