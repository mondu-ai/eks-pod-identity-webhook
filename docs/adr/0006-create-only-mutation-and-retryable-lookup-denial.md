# ADR-0006: Mutate only on CREATE; deny a failed ServiceAccount lookup for a retry

- **Status:** accepted
- **Date:** 2026-11-04

## Context

The webhook decides a pod's credentials from its ServiceAccount, which it reads with a live `ServiceAccounts().Get()` during admission. Three behaviors around that decision let pods start without credentials or blocked them for no reason:

- The chart registers the webhook for `CREATE` and `UPDATE`. A pod's volumes and env cannot change after creation, so for a pod admitted without injection, every later `UPDATE` got a patch that the apiserver rejected, and with it the whole update.
- A failed lookup denied the pod with a 500. client-go retries a 5xx only when the response carries `Retry-After`, so most callers took the 500 as final.
- The lookup had no deadline of its own, and client-go's default rate limit (5 QPS, burst 10) queued a burst of lookups. A lookup that outlived the apiserver's webhook timeout (10s by default) made the apiserver give up, and `failurePolicy: Ignore` admitted the pod unmutated.

## Decision

We will mutate only `CREATE`. Every other operation is allowed unmutated, without a lookup.

We will deny a pod whose ServiceAccount lookup fails with 503 `ServiceUnavailable` and `Details.RetryAfterSeconds`, which the apiserver turns into a `Retry-After` header. The lookup has a 3s timeout, and the webhook's kube client has no client-side rate limit (`QPS = -1`), as the apiserver's own webhook client does. A pod that fails to deserialize, or whose patch fails to build, is still denied with a 500.

## Consequences

- A lookup failure delays a pod instead of starting it without credentials. Clients built on client-go, the built-in controllers among them, retry up to 10 times.
- Clients that do not honor `Retry-After` on a POST see the 503 as an error.
- A lookup now decides well inside the apiserver's webhook timeout, so a slow apiserver produces retried denials, not silent admissions.
- Each retry calls the webhook and the apiserver again. During an apiserver slowdown one pod creation can cost up to 11 lookups. An informer cache would take the live lookup off the admission path; it is a separate change.
- Every pod in a matched namespace depends on the lookup succeeding. The chart keeps system namespaces out of the webhook's scope.

## Alternatives Considered

- **Admit unmutated when the lookup fails.** The pod starts without credentials and fails at runtime, with nothing in the admission path to show why. This is the outcome the decision exists to prevent.
- **Keep the 500.** It denies just as firmly but is terminal for most callers, so a transient apiserver error turns into a failed pod creation.
- **Only drop `UPDATE` from the chart's rules.** It fixes the rejected updates, but leaves the webhook wrong for any configuration that still sends `UPDATE`.
- **Informer cache now.** It removes the live lookup, but needs its own readiness and cache-miss handling; it follows separately.
