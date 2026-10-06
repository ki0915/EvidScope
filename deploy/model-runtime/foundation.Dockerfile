# Reviewed offline runtime image must contain /app/llama-server and Python.
# Pin its digest in the build invocation, then pin this resulting image in the lock.
ARG FOUNDATION_RUNTIME_IMAGE
FROM ${FOUNDATION_RUNTIME_IMAGE}
COPY deploy/model-runtime/foundation_entry.py /app/foundation_entry.py
USER 10001:10001
ENV HF_HUB_OFFLINE=1 PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python", "/app/foundation_entry.py"]
