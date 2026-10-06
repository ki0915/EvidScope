# Independent fresh-controller and supplier-evidence review

Reviewed the fresh integration in `scripts/run-public-qa-job.mjs`, `scripts/score-public-qa-fresh.mjs`, their focused tests, `public/app.js` supplier changes, and the supplier path in `src/kr-governance-evidence.mjs`. Supporting workload/verifier and service/finance intake paths were read to check the actual boundaries. No code or runtime was changed; this report is the only review edit. No GPU, Docker, Kubernetes or PVC actions were performed.

**No release-blocking defect was found within this bounded review.** The new controller mode rejects training/pilot/resume/other diagnostic combinations before side effects, uses the dedicated source80/fresh128 workload, persists exact Job/Pod identities and scoped mounts, retains measured resource guards and UID-bound cleanup, and leaves training completion/quality/promotion unclaimed. A terminal resource-read race rechecks the same Pod/container and fresh mounts; neither missing telemetry nor a successful process exit substitutes for independent artifact verification. The separate fresh verifier also checks exact command/arguments/environment/security/resource/runtime identity and the 256-call baseline-before-candidate sequence.

The scorer keeps exactly128 outputs on each side, the fixed128-token/120-second measurements and original human spans, and does not silently shrink the denominator. It expressly leaves actual model execution and quality/promotion false. Root and agent runner output contracts agree. The frozen Python runner remained unchanged at SHA `896dc88599333e608133fa0ff4a1b0853fcea9d3e83469fca20f79eefdd51dbe` during this review.

## Supplier scope and security

Supplier alternatives are defined only for `KR-34-RISK`, `KR-34-EXPLAIN` and `KR-34-PROTECT`. They require an authenticated authority-source review, exact bundle reference/hash, matching reviewer, full measure/performed measure/change review, current system/requirement/model/policy hashes, original supplied model/purpose, recorded deployer/business-operator role and no substantial modification. Assessment intake verifies covered measures, current scope and retained file recovery; live reporting rechecks document staleness. Wrong or missing review, other models, changed purpose, stale files/bundles and selected conflicting checks remain insufficient. Oversight and document duties have no supplier alternative.

The UI renders hostile values as literal text, displays exact supplier bundle/hash/reviewer and incomplete review reasons, preserves unknown facts and keeps technical support separate from human legal status. API tests exercise actual authenticated intake, restart, tenant denial, corrupt document recovery, revised bundle re-review, signed frozen-report immutability and ledger integrity. This remains a synthetic local document adapter and authenticated reported evidence, not proof of real supplier truth, elapsed five-year retention or legal compliance.

Checked the official current [Decree Article27](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0027&lsiSeq=288781&urlMode=lsScJoRltInfoR) and [Act Article34](https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=0034&lsiSeq=282791&urlMode=lsScJoRltInfoR) on2026-10-06. The decree confines this supplier-performance route to Article34(1) measures1–3, conditional on original-purpose/use and substantial-change review; separate publication and five-year document duties remain. The code/UI boundary agrees with those provisions. This review did not certify every legal condition or validate document meaning.

## Verification performed

| Focused check | Outcome |
|---|---|
| Fresh controller, scoring, workload and preparation |14/14 passed|
| Existing controller terminal/retry and diagnostic workload compatibility |31/31 passed|
| Korean typed evidence pure tests |60/60 passed|
| Supplier pure and actual HTTP integration, IPv6 elevated execution |4/4 passed|
| Finance/governance/language UI tests |31/31 passed|
|`node --check public/app.js`|Passed|

The UI tests use the repository's VM DOM harness; they do not establish real-browser visual correctness. The fresh tests and compatibility checks do not establish actual GPU generation. That remains root-owned and must pass the independent runtime/artifact verifier.

Preserved environmental failures: first combined supplier run passed63 pure tests but actual HTTP failed `connect EACCES 127.0.0.1:58795`; elevated IPv4 rerun failed vault startup with `listen EFAULT 127.0.0.1:58197`; sandbox IPv6 rerun failed `connect EACCES ::1:55133`. The same unchanged supplier test passed4/4 with `EVIDSCOPE_TEST_HOST=::1` under elevated local execution. These failures were not converted into a passing product assertion and no listener/code workaround was added.

## Nonblocking report clarity finding

At review time `scripts/score-public-qa-fresh.mjs` summary `failures` selected only truthy `row.failure`. The reused `scoreResponse` returns `passed:false` with `failure:null` for semantic mistakes such as a wrong exact answer, missing grounded quote or incorrect abstention. Therefore aggregate pass counts and row flags remain correct, but the summary failure list omits these mistakes. Suggested improvement: add semantic reason labels in the new scorer's summary layer while preserving the old shared `scoreResponse` contract. Parent was informed; no patch was made by this reviewer.
