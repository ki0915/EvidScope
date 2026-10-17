#!/usr/bin/env bash
# Prepare a rented GPU for the judge round (docs/rented-gpu.md): one venv with pinned packages and the torch build that matches the
# card (Blackwell, compute capability 12.x, needs CUDA 13 wheels; older cards take the CUDA 12.6 wheels). The installed package list's
# digest becomes the training identity's image id (pip-freeze@sha256:...), so a receipt names exactly what trained the adapter.
set -euo pipefail
ROOT=${EVID_ROOT:-/workspace/evid}
VENV=$ROOT/venv
mkdir -p "$ROOT/logs"
cap=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | head -1)
if [ "${cap%%.*}" -ge 12 ]; then index=cu130; else index=cu126; fi
[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q torch==2.13.0 --index-url "https://download.pytorch.org/whl/$index"
"$VENV/bin/pip" install -q transformers==5.16.1 peft==0.21.2 accelerate==1.15.0 bitsandbytes==0.50.2 safetensors==0.8.0
# JEV-9B's Qwen3.5 backbone has gated-delta (linear attention) layers; without these kernels transformers falls back to a slow torch path.
"$VENV/bin/pip" install -q flash-linear-attention==0.5.2 fla-core==0.5.2 || echo '{"warning": "flash_linear_attention_unavailable"}'
"$VENV/bin/python" - <<'PY'
import torch
assert torch.cuda.is_available(), "cuda unavailable"
print({"torch": torch.__version__, "cuda": torch.version.cuda, "devices": [torch.cuda.get_device_name(i) for i in range(torch.cuda.device_count())],
       "capability": torch.cuda.get_device_capability(0), "bf16": torch.cuda.is_bf16_supported()})
x = torch.randn(256, 256, device=0, dtype=torch.bfloat16)
print({"matmulOk": bool(torch.isfinite(x @ x).all())})
import bitsandbytes, transformers, peft
print({"bitsandbytes": bitsandbytes.__version__, "transformers": transformers.__version__, "peft": peft.__version__})
PY
echo "pip-freeze@sha256:$("$VENV/bin/pip" freeze | LC_ALL=C sort | sha256sum | cut -d' ' -f1)" > "$ROOT/image-id"
cat "$ROOT/image-id"
