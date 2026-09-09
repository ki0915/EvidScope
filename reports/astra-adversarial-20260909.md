# Independent adversarial audit — local AI advisory

Date: 2026-09-09. Reviewed integration: `300c07f`, diff from `0b96781`. Reviewer: separate GPT-6 Astra / high context. Requirements were read first from `docs/multi-agent-development.md` and ADR 0004. This is a finding report, not release approval or proof that the feature is secure.

Scope: `src/assistance.mjs`, `src/assistance-runner.mjs`, associated service/server/workbench changes, existing assistance tests, and security-relevant `public/team-support.js` / `public/app.js` integration. The separate development-operations worktree is excluded. No product source was modified. No external model, paid API, real business data, existing UI server, or Ollama daemon was used or stopped. All test input/results are SYNTHETIC. UI remediation remains deferred under the user's instruction.

## Findings

### A1 — P1, conditional on projection-write threat: advisory objects bypass signed-original verification

Locations: `src/assistance.mjs:100`, `:111`, `:129-131`; runner `src/assistance-runner.mjs:22-31`. Related read helpers: `src/store.mjs:45-47`.

Precondition: an attacker or corruption can modify an `objects.body` query projection in the test Vault DB, but cannot edit the append-only ledger, obtain/use the signing key, or modify application code. This is **not** a demonstrated capability of a source account or run-scoped worker. ADR 0004 expressly excludes protection against full host-administrator compromise; the finding is narrower: loss of signed-original/projection consistency, which the existing case workbench otherwise checks.

Actual HTTP reproduction (`node .test-runs/astra-adversarial/probe.mjs`):

1. Create and dispatch a normal synthetic package through human API.
2. Change only the stored `assistance_package` projection's evidence status and `profileSnapshot.instructions`, leaving its `bundleHash`, original ledger and run hash untouched.
3. `GET /internal/assistance/runs/:id/package` with the real issued run credential returns **200** and the injected instructions. The returned bundle's independently recomputed hash differs from the advertised hash. Result submission with the original hash is accepted.
4. In a separate newly queued run, change only its `assistance_run` projection to `completed` and insert a synthetic forged draft, without any worker claim or result API submission.
5. Human run GET returns `completed`, `stale:false`. Human review POST returns **200** and appends an `assistance_review` containing the forged draft. `/api/export` verifies successfully against the test public key: the application has signed the new review based on an unverified projection.

Expected: reject projection/original or content/hash mismatches before handing off data, displaying authoritative run state, or recording a review. Actual: the case context verifier ignores assistance object rows, and new routes trust their projections. A hash string comparison does not bind the content unless the content is independently hashed and compared with its authenticated original.

Additional targeted runner reproduction (`node .test-runs/astra-adversarial/runner-ui-probe.mjs`): mocked fetch returns a modified package with the original hash; the real `runAssistance` function sends the injected profile text into the system message and submits the original hash. Four mocked fetch calls; zero real network requests/inference. This establishes missing runner verification, **not** successful semantic manipulation of Qwen.

Remediation direction: verify/reconstruct assistance packages, profiles, latest run transitions and reviews from authenticated ledger rows before use; compare projections with those originals and validate bundle/profile hashes. Recompute bundle content hash in the runner as defense in depth. Do not rely on `/api/integrity`'s existing event-only projection check to authenticate these object types.

### A2 — P2: case changes do not invalidate advisory freshness

Locations: `src/assistance.mjs:58`, `:90`, `:129`; `src/audit-workbench.mjs:13` (`contextHash` includes tenant/action/events/evaluations/analysis but no case revision).

Precondition: ordinary authorized human case update after a package/run is created; no DB modification or model deception.

Actual HTTP reproduction in `probe.mjs`: prepare, dispatch and complete a synthetic run; POST the case to `status:"closed"` with a new owner, comment and closure reason; GET the run; POST an accept review using the original context hash. Actual values: case status `closed`, context hash unchanged, `stale:false`, review **200**. Expected under the task requirement to preserve stale on case/evidence/catalog change: old package/run becomes stale and cannot be accepted under the old case context.

Impact: the evidence hash alone allows an old advisory to be presented/accepted as current after case scope or human handling has changed. The advisory did not itself close the case; the defect is its freshness binding.

Remediation direction: bind a verified case revision/hash into the assistance snapshot and freshness comparison, including dispatch/review checks. Define which case changes invalidate assistance explicitly, while keeping the model's minimized input free of unnecessary case text.

### A3 — P2: timeout transition is rolled back while the read API simulates it

Locations: `src/assistance.mjs:102-108`, `:117`, `:61`; transaction rollback at `src/store.mjs:28`.

Precondition: a queued/running credential expires naturally. The probe moves the synthetic credential deadline into the past directly, as the existing test does, to avoid a five-minute wait; that is test setup, not an exploit prerequisite.

Actual HTTP reproduction in `probe.mjs`: request an expired run's package. Response **410**. Immediately inspect the synthetic DB and ledger: stored run remains `queued`, `finishedAt` is absent, and the count of `timed_out` ledger records for the run is **0**. Human GET nevertheless reports `state:"timed_out"`.

Expected: expiry is durably recorded once, with finish/error metadata, while claim/result is rejected. Actual: `expireIfNeeded` writes inside `store.transaction`, then `fail(410)` causes the same transaction to roll back. The result route uses the same pattern. Human decoration masks the missing transition; the existing test checks only the decorated GET, so passes.

Remediation direction: commit an expired transition separately from the HTTP error path, or return a transaction result that the caller translates to 410 after commit. Ensure passive/unclaimed expiry has a defined durable reconciliation mechanism. Preserve idempotency. This test does **not** show expired tokens being accepted or the concurrency lock being bypassed.

### A4 — P2, UI deferred: dispatch preview omits part of the model input

Location: `public/team-support.js:166-183` (`packagePreview`), particularly `:179-181`; full package is sent by `src/assistance-runner.mjs:16` and `:28`.

Precondition: a normal prepared package contains `governanceSnapshot`, which every package does; it contains active rule identifiers and, for governance roles, catalog mappings.

Reproduction in `runner-ui-probe.mjs`: execute the actual renderer with a small synthetic text DOM and a package containing distinctive governance/rule strings. Neither `SYNTHETIC-RESTRICTED-RULE-ID` nor `SYNTHETIC-GOVERNANCE-PAYLOAD` appears anywhere in the rendered preview. Evidence, profile and analysis snapshots are rendered. The subsequent dispatch control is available without a full-package viewer.

Expected: the person can inspect all transmitted content before explicit dispatch, including potentially sensitive identifiers. Actual: governance content is passed into inference but omitted from the only pre-dispatch preview. Trusted catalog status does not remove the preview requirement for the complete payload.

Remediation direction (deferred): show the entire frozen input, or render every field including governance and offer an exact JSON view/download before dispatch. Keep this separate from a claim that metadata is completely anonymized. Browser layout/accessibility was not tested by this text-DOM probe.

### A5 — P2, UI deferred: accepted edited text is not shown in review history

Locations: `public/team-support.js:336-355`, `:358-364`.

Precondition: a person edits a machine draft and accepts it through the existing UI/API.

Reproduction in `runner-ui-probe.mjs`: execute the actual `runDetailNode` with an original draft summary and a distinct accepted `reviews[0].draft.summary`. The rendered detail includes `SYNTHETIC ORIGINAL REJECTED WORDING` and an acceptance label, but does not contain `SYNTHETIC EDITED ACCEPTED WORDING`. The history renders only action, reviewer, timestamp and reason, while the draft panel always renders `run.draft`.

Expected: visibly distinguish the machine original from the exact version accepted by each human review. Actual: reopening the reviewed run shows the original next to an acceptance indicator without the human correction, obscuring which content was accepted. The API correctly preserves the edited draft; no case or compliance state mutation was demonstrated.

Remediation direction (deferred): render each review's preserved draft or a clearly labeled diff and the latest accepted version; label it as advisory adoption rather than business/compliance approval.

## Test evidence and negative controls

Commands executed from repository root:

```text
node --test --test-concurrency=1 test/assistance-runner.test.mjs test/assistance.test.mjs
node .test-runs/astra-adversarial/probe.mjs
node .test-runs/astra-adversarial/runner-ui-probe.mjs
```

- Existing suite: **8 passed, 0 failed**. Covers fixed local model policy, profile writer roles, metadata minimization, other-tenant package denial, run-credential isolation/replay, global cross-tenant claim lock, invalid/foreign refs, result count bounds, evidence/catalog staleness and decorated timeout display.
- New real HTTP probe: all assertions passed. Other tenant's package GET **404**; source account package GET **403**; run credential used to write a human case decision **401**. Accepting an advisory containing synthetic "approved and fully compliant" text leaves actual case decisions unchanged. This is evidence of the structural advisory/decision boundary, not validation of that wording.
- New runner/UI probes: all assertions passed, using actual functions and synthetic mocks. Real model quality, semantic injection resistance and physical GPU serialization were **not** tested.
- First sandbox HTTP probe attempt failed before assertions with Windows `listen EFAULT` on its own temporary `127.0.0.1` Vault. The unchanged probe then passed with authorized elevated execution. No product/harness code was modified to hide the environment failure. The original suite ran successfully in its initial invocation.
- Full details: `.test-runs/astra-adversarial/probe.mjs`, `results.json`, `runner-ui-probe.mjs`, `runner-ui-results.json`. Scratch harnesses generate only their own synthetic config/DB/key material; credentials are not printed in the report/output. All started harness children are closed in `finally`.

## Boundaries and remaining gaps

No source/worker/run credential escape to other tenants or human decision APIs was reproduced. No cloud fallback, recursive delegation, model tools, DB/key/human credential transfer from the official runner code was found in this pass. Provider identity/usage fields are explicitly reported visibility metadata, not verified attestation; absence remains null in the tested fixture. No proof of actual Ollama inference is inferred from a submitted synthetic `providerReportedModel` string.

The documented physical model-daemon concurrency control, actual five-minute wall-clock cancellation, kill/restart behavior, real model injection quality, Windows credential-file ACLs, full browser accessibility, and deployment isolation require separate tests. A compromised full host administrator remains outside the stated ADR boundary. This reviewer does not implement or self-close these findings.
