# Architecture Decision Records

An ADR captures a single architectural decision — the context that forced it, what was decided, and the consequences we accept. They exist so the *why* survives after the people who made the call move on.

## When to write one

Write an ADR when a decision is hard to reverse or shapes the system going forward. For this project that includes things like:

- Changing anything in the EKS IRSA injection contract (annotation key, token audience, mount path, env var set) — these are load-bearing and any deviation must be justified in writing.
- Altering the fail-open / fail-closed admission semantics.
- Moving off the flat single-package layout, or splitting into more modules.
- Changing the deployment/distribution model (chart source, registry, TLS strategy, cert-manager vs. baked certs).
- Adopting or dropping a core dependency (Gin, controller-runtime certwatcher, the k8s client).

Skip ADRs for routine changes — bug fixes, dependency bumps, refactors that don't change a contract.

## Convention

- Filename: `NNNN-kebab-case-title.md`, zero-padded sequential number — e.g. `0001-flat-single-package-layout.md`, `0002-certwatcher-tls-hot-reload.md`. Easy to reference ("see ADR-2"), trivially sortable.
- Copy `TEMPLATE.md` to start.
- ADRs are **immutable once accepted.** Don't rewrite history — to change a decision, write a new ADR that supersedes the old one and link both ways (set the old one's status to `superseded by ADR-N`).
