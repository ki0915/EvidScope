#!/usr/bin/env bash
# The judge round on a rented GPU (docs/rented-gpu.md), after setup.sh and the two fetch_base.py runs: train Qwen3-4B (GPU 0) and
# JEV-9B (GPU 1) side by side on in/train.jsonl, then run every request set in in/requests through four judges: each base untrained
# (qwen-zero, jev-zero) and trained (qwen-cand, jev-cand). Results land in results/<judge>/<set>.{outputs,logprobs,receipt}.json for
# scripts/judge-round.mjs score on the PC; logs in logs/, the current stage in status.txt. A stage that fails stops its own chain only.
set -uo pipefail
ROOT=${EVID_ROOT:-/workspace/evid}
cd "$ROOT"
PY=$ROOT/venv/bin/python
S=$ROOT/scripts
QWEN=$ROOT/models/qwen
JEV=$ROOT/models/jev
QRUN=${QRUN:-/checkpoints/session-inference/run}
JRUN=${JRUN:-$ROOT/jev-run}
export EVIDSCOPE_RENTED_GPU=1 EVIDSCOPE_TRAINING_IMAGE="$(cat "$ROOT/image-id")" PYTHONUNBUFFERED=1
mkdir -p logs results "$(dirname "$QRUN")"
status() { echo "$1 $(date -u +%FT%TZ)" >> status.txt; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

qwen_chain() {
  export CUDA_VISIBLE_DEVICES=0
  local revision; revision=$($PY -c "import json; print(json.load(open('$QWEN/artifact-lock.json'))['revision'])")
  status "qwen training"
  EVIDSCOPE_BASE_REPOSITORY=Qwen/Qwen3-4B-Instruct-2507 EVIDSCOPE_BASE_REVISION=$revision EVIDSCOPE_DATASET_SHA256=$(sha in/train.jsonl) \
  EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256=$(sha "$QWEN/artifact-lock.json") \
    $PY "$S/train-governance-mapping-lora.py" --task session-inference --rented-gpu --data in/train.jsonl --model-dir "$QWEN" \
      --base-repository Qwen/Qwen3-4B-Instruct-2507 --base-revision "$revision" --output "$QRUN" --compute-dtype bfloat16 \
      --pause-ratio 0 --thermal-max-wait-seconds 0 --epochs "${QWEN_EPOCHS:-1}" > logs/train-qwen.log 2>&1 || { status "qwen training failed"; return 1; }
  status "qwen trained"
  for judge in qwen-zero qwen-cand; do
    [ "$judge" = qwen-zero ] && [ -n "${SKIP_ZERO:-}" ] && continue
    mkdir -p "results/$judge"
    for requests in in/requests/*.jsonl; do
      set_name=$(basename "$requests" .jsonl)
      adapter=(); [ "$judge" = qwen-cand ] && adapter=(--adapter "$QRUN/candidate")
      $PY "$S/session_judge_generate.py" --model-dir "$QWEN" "${adapter[@]}" --requests "$requests" --prefix "results/$judge/$set_name" \
        >> "logs/eval-$judge.log" 2>&1 || status "qwen eval failed $judge $set_name"
    done
    status "qwen evaluated $judge"
  done
}

jev_chain() {
  export CUDA_VISIBLE_DEVICES=1
  status "jev training"
  $PY "$S/train_jev_decision.py" train --model-dir "$JEV" --data in/train.jsonl --output "$JRUN" --epochs "${JEV_EPOCHS:-1}" > logs/train-jev.log 2>&1 \
    || { status "jev training failed"; return 1; }
  status "jev trained"
  for judge in jev-zero jev-cand; do
    [ "$judge" = jev-zero ] && [ -n "${SKIP_ZERO:-}" ] && continue
    mkdir -p "results/$judge"
    if [ "$judge" = jev-zero ]; then a=$JEV/adapter; h=$JEV/head.safetensors; c=$JEV/calibration.json
    else a=$JRUN/candidate/adapter; h=$JRUN/candidate/head.safetensors; c=$JRUN/candidate/calibration.json; fi
    for requests in in/requests/*.jsonl; do
      set_name=$(basename "$requests" .jsonl)
      $PY "$S/train_jev_decision.py" predict --model-dir "$JEV" --adapter "$a" --head "$h" --calibration "$c" --requests "$requests" \
        --prefix "results/$judge/$set_name" >> "logs/eval-$judge.log" 2>&1 || status "jev eval failed $judge $set_name"
    done
    status "jev evaluated $judge"
  done
}

# "run.sh fill" (after a round) runs only the judge/set pairs whose outputs are missing, for example after a failed evaluation.
fill() {
  for judge in qwen-zero qwen-cand jev-zero jev-cand; do
    for requests in in/requests/*.jsonl; do
      set_name=$(basename "$requests" .jsonl); prefix=results/$judge/$set_name
      [ -e "$prefix.outputs.json" ] && continue
      mkdir -p "results/$judge"
      case $judge in
        qwen-zero) CUDA_VISIBLE_DEVICES=0 $PY "$S/session_judge_generate.py" --model-dir "$QWEN" --requests "$requests" --prefix "$prefix" ;;
        qwen-cand) CUDA_VISIBLE_DEVICES=0 $PY "$S/session_judge_generate.py" --model-dir "$QWEN" --adapter "$QRUN/candidate" --requests "$requests" \
                     --prefix "$prefix" ;;
        jev-zero) CUDA_VISIBLE_DEVICES=1 $PY "$S/train_jev_decision.py" predict --model-dir "$JEV" --adapter "$JEV/adapter" --head "$JEV/head.safetensors" \
                    --calibration "$JEV/calibration.json" --requests "$requests" --prefix "$prefix" ;;
        jev-cand) CUDA_VISIBLE_DEVICES=1 $PY "$S/train_jev_decision.py" predict --model-dir "$JEV" --adapter "$JRUN/candidate/adapter" \
                    --head "$JRUN/candidate/head.safetensors" --calibration "$JRUN/candidate/calibration.json" --requests "$requests" --prefix "$prefix" ;;
      esac >> "logs/fill-$judge.log" 2>&1 && status "filled $judge $set_name" || status "fill failed $judge $set_name"
    done
  done
}
if [ "${1:-}" = fill ]; then fill; exit 0; fi

# Both chains by default; "run.sh qwen" or "run.sh jev" reruns one (with QRUN or JRUN pointing at a new output directory).
# SKIP_ZERO=1 leaves out the untrained judges, for a later round on the same request files: their outputs would not change.
chains=${1:-both}
status "round started $chains $(sha in/train.jsonl)"
qs=skipped; js=skipped
[ "$chains" = jev ] || { qwen_chain & q=$!; }
[ "$chains" = qwen ] || { jev_chain & j=$!; }
[ -n "${q:-}" ] && { wait "$q"; qs=$?; }
[ -n "${j:-}" ] && { wait "$j"; js=$?; }
status "round finished $chains qwen=$qs jev=$js"
