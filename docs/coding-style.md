# Coding Style

Codified from `.golangci.yml` (golangci-lint **v2**, pinned to `v2.12.2`) and the de-facto patterns in `main.go`. The linter is the source of truth — when in doubt, run `make lint`.

## Formatting & tooling

- **`make fmt`** runs `go fmt` + `goimports`. Formatting is non-negotiable; CI runs `make ci` which includes it.
- **`make lint`** installs the pinned golangci-lint and runs it over the root module. `make vet`, `make security` (gosec → `results.sarif`) round out the checks. All three exclude `e2e/` (separate module).
- **`make test`** — unit tests with `-race -timeout=30s`.

## Enforced limits (they fail CI)

- **Function length** (`funlen`): 100 lines / 50 statements. This is *why* the code is a flat package of small methods rather than a few big handlers — don't grow a function past the limit, decompose it.
- **Cyclomatic complexity** (`cyclop`, `gocyclo`): 15 max.
- **Duplication** (`dupl`): 100-token threshold — extract shared logic instead of copy-paste.
- **Naked returns** (`nakedret`): only in functions ≤30 lines.
- **Magic strings** (`goconst`): a string literal ≥3 chars appearing ≥3 times must be a named const. (See the const block at the top of `main.go`.)

Test files (`_test.go`) are exempt from `gosec`, `funlen`, `goconst`, `dupl`, `gocyclo`. `e2e/` is excluded entirely.

## Error handling

- **Wrap with context:** `fmt.Errorf("failed to get ServiceAccount %s/%s: %w", ns, name, err)`. `errorlint` enforces `%w` and correct comparison; `errname` enforces sentinel `ErrXxx` / type `XxxError` naming.
- **`errcheck` is strict:** `check-type-assertions` and `check-blank` are on. You must handle the `ok` of a type assertion and cannot silently `_ =` an error to dodge the check — if you genuinely intend to ignore one (e.g. cleanup in a `defer`), annotate it: `//nolint:errcheck // cleanup in defer` (as the e2e tests do).
- **Flat error checks, no nesting.** `errors.Is(err, sentinel)` first, then `if err != nil`. Never `if err != nil { if errors.Is(...) }`.

## Naming, comments, structure

- **`govet` runs `enable-all`** (minus `fieldalignment` and `shadow`). Expect strict vet.
- **`revive` requires:** doc comments on exported identifiers (`exported`), a package comment (`package-comments` — see the top of `main.go`), Go-idiomatic names (`var-naming`), error-return / error-naming conventions.
- **File declaration order:** `const` → `var` → `type` → exported functions → unexported functions. Keep declarations grouped at the top, not scattered between functions. `main.go` already follows this.
- **Comment the WHY, not the WHAT.** The existing `#nosec Gxxx - <reason>` inline comments are the model: terse, justify a specific decision (why a constant that looks like a secret isn't). No narration, no restating the code.
- **Leveled logging only.** Use `logInfo`/`logWarn`/`logError`/`logDebug` (+ `f` variants). No bare `fmt.Println`/`log.Print`. `LOG_LEVEL=debug` gates the debug logger.

## gosec

Severity and confidence both `medium`. Standard-but-secret-looking constants (env var names, mount paths, audiences) are annotated inline with `#nosec G101 - <reason>` — follow that pattern rather than disabling the linter globally.

## Architecture-level rules

- **Stay flat.** One `package main` at root. Don't introduce `internal/`/`pkg/` layering unless a genuine reusable boundary emerges — the small-function decomposition is the intended shape, not a stopgap.
- **Keep the two modules separate.** Root and `e2e/` are independent Go modules. Don't import the e2e framework from the webhook or vice versa.
- **Don't touch the IRSA contract constants' *values*.** They're wire-compatible with EKS by design (see `ARCHITECTURE.md`). Renaming the Go identifier is fine; changing the string/number it holds is a breaking change.
- **Preserve idempotency and fail semantics.** New injection logic must check-before-add (never overwrite user config) and keep the allow-non-pod / deny-on-error asymmetry.
