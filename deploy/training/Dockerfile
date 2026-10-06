# Supply an approved CUDA/Python base by immutable digest. No default remote pull.
ARG TRAINING_BASE_IMAGE
FROM ${TRAINING_BASE_IMAGE}
USER root
COPY deploy/training/requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir -r /app/requirements.txt && python -m pip freeze --all > /app/installed-packages.txt
COPY scripts/train-foundation-lora.py scripts/training_artifacts.py scripts/training-paired-eval.py scripts/training-probe.py /app/
RUN chmod -R a+rX /app
USER 10001:10001
ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 WANDB_DISABLED=true PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 TOKENIZERS_PARALLELISM=false
WORKDIR /app
ENTRYPOINT ["python", "/app/train-foundation-lora.py"]
