# ADR-0007: On shutdown, drain until kube-apiserver closes its connections

- **Status:** accepted
- **Date:** 2026-11-04

## Context

kube-apiserver calls webhooks over HTTP/1.1 and keeps idle keep-alive connections for reuse for 90s (`http.DefaultTransport.IdleConnTimeout`). If a server closes a connection just as the apiserver sends a request on it, the call fails, the apiserver does not retry the POST, and `failurePolicy: Ignore` admits the pod unmutated.

The server closed connections in two places. Its idle timeout was 60s, shorter than the apiserver's, so connections the apiserver still held expired under it. On SIGTERM, `Shutdown` closed every idle connection at once while the apiserver kept sending on them: removing a replica from the Service endpoints stops new connections, not traffic on established ones. Under load, both showed up as pods admitted without credentials.

Only the client can close an idle keep-alive connection without that race.

## Decision

We will keep idle connections for 120s, longer than the apiserver does, and serve HTTP/1.1 only.

On the first SIGTERM or SIGINT, the server drains: every response carries `Connection: close`, so the apiserver drops each connection after using it. The server keeps serving for at least 10s, while the replica leaves the Service endpoints, and then until clients have closed every connection or the drain timeout passes. Only then does it call `Shutdown`. A second signal ends the process at once.

The drain timeout comes from `SHUTDOWN_DRAIN_TIMEOUT` and defaults to 20s, which with the 5s `Shutdown` fits Kubernetes' default 30s grace period. The chart sets it to 100s, above the apiserver's 90s, and `terminationGracePeriodSeconds` to 120.

## Consequences

- With the chart's values, a stopping replica waits until the apiserver has closed every connection to it, so no admission fails on a connection the server closed.
- A stopping replica can take up to 105s to exit, which slows rollouts and node drains.
- The chart's `terminationGracePeriodSeconds` must cover the drain timeout plus 5s. If it does not, the kubelet kills the replica mid-drain.
- With the 20s default, connections the apiserver does not use during the drain are still closed by `Shutdown`, so the race remains possible there. An image running under an older chart is no worse than before, and the full fix arrives with the chart's values.
- An environment variable, unlike a flag, is ignored by older images, so a newer chart does not crash an older webhook.

## Alternatives Considered

- **`http.Server.SetKeepAlivesEnabled(false)` on SIGTERM.** It closes idle connections immediately, which is the race itself.
- **A fixed delay before `Shutdown`, in code or as a `preStop` sleep.** Connections the apiserver used during the delay close cleanly, but the ones it did not use are still closed by `Shutdown` and race their next use.
- **HTTP/2 with `GOAWAY`.** The apiserver forces HTTP/1.1 for webhooks.
- **A flag for the drain timeout.** An older image rejects an unknown flag and crashes, which takes the webhook down and admits every pod unmutated.
