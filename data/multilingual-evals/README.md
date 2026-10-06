# Multilingual synthetic review candidates

This is a deterministic template pool, not independently collected evidence or a measured model benchmark.

- Audit: 180 fact families, each in English, Korean and mixed text (540 rows). Split counts: tune 300, validation 60, test 180. English evidence IDs remain stable across translations.
- Cipher: 60 families in three language variants (180 rows). Includes all 12 privacy categories, keyword-only, masked, ambiguous, long-tail and instruction-injection examples.
- Every row remains `UNREVIEWED`, `humanReviewed:false`, `piiReviewed:false`. `expectedOutput` is a review suggestion; only the human-review importer may produce `approvedOutput`.
- Candidate privacy labels are intentionally unapproved. Reserved/test/dummy values may be Safe under the selected policy; a reviewer must resolve each label before use. The strings are not collected personal data or operational credentials.
- Related translations stay in one split by a language-neutral fact hash. Templates recur across splits; this pool cannot justify production performance or independence claims.
- A long-text candidate label describes the complete text. Runtime coverage must be measured with the real tokenizer; incomplete coverage must never be silently reported as Safe.

Regenerate with `node scripts/generate-multilingual-evals.mjs`. The generator refuses to overwrite any reviewed candidate file. Human-reviewed outputs should be written to a separate approved dataset.
