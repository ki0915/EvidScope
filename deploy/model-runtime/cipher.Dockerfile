# Supply a reviewed digest-pinned Python image and an offline, hash-locked wheelhouse.
# Build with network disabled after acquiring dependencies in the approved staging area.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
COPY wheelhouse /wheelhouse
COPY requirements.lock /requirements.lock
RUN python -m pip install --no-index --find-links=/wheelhouse --require-hashes -r /requirements.lock
COPY deploy/model-runtime/cipher_service.py /app/cipher_service.py
USER 10001:10001
ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python", "/app/cipher_service.py"]
