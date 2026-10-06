# Fresh paired generation runner

Implemented `scripts/evaluate-public-qa-fresh.py` and CPU guards in `test/test_public_qa_fresh.py`. Existing diagnostic, training and source contracts were left unchanged. No Docker, Kubernetes, PVC or GPU actions were performed by this implementation task.

The runner pins the original fresh128 data/manifest (`dc8a7bb0c9eb9de9abbc6f3cea39851453db8c60cc91602223f3a9aaeb628142` / `c131723029cd014d718974bb426098925f02f6d4ced914637791e3fb76596ed1`) and the actual source80 run `public-qa-grounding-20261006-r3`. It verifies the sealed candidate's complete inventory, exact adapter, independent verification report, provenance and raw CRI receipt. Source global step remains 20; total adapter history is 80. The original controller observation error is preserved through its pinned verification report and CRI reconciliation rather than rewritten as success.

## CLI and inputs

```text
python /runtime/evaluate-public-qa-fresh.py
  --data /data/fresh/data.jsonl
  --manifest /data/fresh/manifest.json
  --binding /bindings/binding.json
  --verification /bindings/verification.json
  --provenance /bindings/provenance.json
  --cri-inspection /bindings/cri-inspect.json
  --model-dir /models/foundation-base
  --adapter-dir /adapters/candidate
  --output /checkpoints/fresh-evaluations/public-qa-fresh-<suffix>
```

`--token-check` performs the same source/data checks and strict admission, with zero model calls. The output must be a new direct child matching the binding run ID. Required environment: `EVIDSCOPE_ISOLATED=1`, pinned `EVIDSCOPE_TRAINING_IMAGE`, `EVIDSCOPE_FRESH_EVALUATION_BINDING_SHA256`, and the existing six `EVIDSCOPE_DIAGNOSTIC_{DATA,MANIFEST,CONTROLLER,VERIFICATION,CANDIDATE,ADAPTER}_SHA256` bindings. Actual generation also waits for the existing memory controller and thermal gate. Runtime imports require the existing diagnostic helper, training artifact helper and CUDA/memory/thermal helpers; no new third-party dependency was added.

All 128 full contexts must pass actual tokenizer admission before model loading or generation. Any excluded row fails the run; it cannot silently reduce the evaluation set. Input prompts reuse the exact existing Korean SYSTEM and only question/document fields. Answers, answerability labels, original annotations and provenance metadata are excluded from model prompts.

## Execution and artifacts

One frozen local Reasoning base is loaded with NF4 double quantization and BF16 compute/model dtype; the source80 adapter is attached once, frozen and evaluated. Baseline128 uses `disable_adapter()`, followed by candidate128 on the same model object. Actual adapter module states are checked for each side, and actual input tensor IDs must hash to the admitted IDs. Each request uses context1024, output128, seed42, no sampling and a 120-second generation limit. GPU allocator fraction0.65 is not a whole-GPU isolation guarantee. Sequential order and warm caches limit latency comparisons.

Outputs: `preadmission.json`, `responses.json`, `progress.json`, `evaluation-receipt.json`, and 256 `rows/{baseline,candidate}-<id>.json` on complete generation. Responses are keyed by side and original row ID. Each includes content/timing/token-limit/timeout measurements plus actual input ID hash, prompt hash, call ordinal and adapterEnabled. Canonical hashes use the existing `canonical_hash`: compact sorted-key Unicode JSON; prompt payload is `messages_for(row)`, input payload is the flat integer input-ID array.

The receipt includes source pins/history, observed BF16 quantization compute dtypes, adapter states, same-base model lifecycle, side timing/GPU peaks, cgroup snapshots and a complete output hash inventory excluding the receipt itself. Partial errors/interruptions preserve generated rows and receipts. Successful generation requires exactly 256 calls, 128 per side, and a second source candidate inventory verification. This does not itself verify controller termination or confer quality: `controllerExecutionVerified`, `qualityClaimAllowed` and `promotionAllowed` remain false pending independent external validation.

## CPU verification

`python test/test_public_qa_fresh.py -v`: **11/11 passed**. Checks use the real frozen128 data and source80 artifacts; reject wrong source/history/pins/claims, changed spans/privacy, duplicate families, altered dataset bytes, reused output paths, admission reordering and a single over-budget context. They verify no label leakage, exact baseline-before-candidate sequence, actual adapter-state guard behavior and CLI defaults. `python -m py_compile scripts/evaluate-public-qa-fresh.py` passed. Fake tokenizer/adapter modules test guards, not actual model inference; no claim of GPU generation is made by these CPU tests.
