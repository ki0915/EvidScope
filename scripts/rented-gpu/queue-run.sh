#!/usr/bin/env bash
# Round queue on the instance: one loop per chain (qwen on GPU 0, jev on GPU 1) runs the rounds listed in /workspace/queue/<chain>.txt
# in order, one at a time. A round directory /workspace/<round> must hold in/, image-id and the venv/models/scripts symlinks, and a
# READY file once its uploads are verified. The queue file is re-read before each round, so rounds can be added or dropped while it runs.
# Start: setsid nohup bash /workspace/queue/queue-run.sh qwen >> /workspace/queue/qwen.out 2>&1 &   (and the same with jev)
set -uo pipefail
CHAIN=$1
case $CHAIN in qwen|jev) ;; *) echo "usage: queue-run.sh qwen|jev"; exit 2;; esac
Q=/workspace/queue/$CHAIN.txt
log() { echo "$CHAIN $1 $(date -u +%FT%TZ)" >> /workspace/queue/queue.log; }
log "loop started"
while :; do
  next=""
  while read -r r; do
    [ -z "$r" ] && continue
    s=/workspace/$r/status.txt
    grep -q "$CHAIN evaluated $CHAIN-cand" "$s" 2>/dev/null && continue
    grep -q "$CHAIN training failed" "$s" 2>/dev/null && continue
    next=$r; break
  done < "$Q"
  if [ -z "$next" ]; then log "queue empty"; exit 0; fi
  if [ ! -f "/workspace/$next/READY" ] || [ ! -s "/workspace/$next/image-id" ]; then log "waiting for $next"; sleep 300; continue; fi
  log "start $next"
  EVID_ROOT=/workspace/$next QRUN=/checkpoints/session-inference/${next#evid-} JRUN=/workspace/$next/jev-run QWEN_EPOCHS=2 JEV_EPOCHS=1 SKIP_ZERO=1 \
    bash /workspace/evid/scripts/run.sh "$CHAIN"
  log "end $next"
done
