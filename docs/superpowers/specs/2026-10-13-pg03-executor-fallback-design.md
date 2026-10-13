# PG03 Executor Phase 2.1: bounded Codex SSE fallback

## Scope

Extend only the guarded Codex HTTP Responses SSE execution path in the PG03
executor worktree. Do not change Gateway, database policy, Billing, non-stream
execution, count-tokens, or the frozen C5 source candidate.

## Approved design

Maintain a request-local chain of at most four distinct account candidates.
Keep account selection and provider invocation in executeStreamMixedOnce.
Continue only after a trusted lease-minted NOT_STARTED FINAL, with durable
zero-dispatch evidence. Carry the complete prior proof chain into admission.
Re-read every ancestor receipt before admitting the next account. Each ancestor
must match the request, attempt, model and process identity, have a unique
account and receipt, and link to the immediately preceding receipt.

The original C5 single-parent verifier remains strict. A PG03-only verifier
uses the same durable-record validation with an explicitly validated chain.
The chain is internal, not sourced from headers or Gateway policy.

All accounts share the existing atomicPoolAttempt dispatch budget. Never reset
that budget on rotation. STARTED, UNKNOWN, dispatch, uncertain fences, invalid
receipts, cancellation, preparation errors and admission errors terminate the
guarded request. No retry round or fifth account is allowed. Existing normal
streaming execution remains unchanged.

## Acceptance

- A/B reject locally; C dispatches and completes: dispatch counts 0/0/1.
- A/B/C/D reject with valid evidence: stop without a fifth candidate.
- STARTED, UNKNOWN, dispatched, uncertain fence or invalid receipt: stop.
- Reject duplicate accounts, broken parent links and mutated ancestor files.
- Preserve the original verifier's rejection of multi-level parents.

## Validation

Add deterministic chain tests and guarded executor integration tests. Run Go
formatting, focused tests, package regression tests and a server build. Durable
receipt tests require Linux process and filesystem attestation; report skipped
or unavailable validation rather than weakening platform security checks.

## Implementation validation

Validated with Linux Docker and Go 1.26.1. Focused PG03 tests, the race detector,
existing receipt tests, capacity receipt tests, executor package tests and the
server build pass. The success fixture verifies the durable receipt parent
links, STARTED+COMPLETED FINAL, account order and per-account dispatch totals.

The complete auth package has four existing failing top-level tests, reproduced
on the unchanged f2c964d baseline using the same container:

- TestPoolGuardOrdinary400StopsBeforeSecondAccount
- TestPoolGuardStreamConcurrencyAndSingleAttempt
- TestPoolIdentityLeaseAndSnapshotBindCanonicalDigest
- TestPoolStage1BActualProcessTrustRecovery (trusted child)

These tests fail with pool admission errors; they are not changed in this phase.
No staging deployment or live-provider validation has been performed.
