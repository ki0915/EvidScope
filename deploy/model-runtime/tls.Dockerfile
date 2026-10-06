ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
COPY deploy/model-runtime/tls_frontend.py /app/tls_frontend.py
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python", "/app/tls_frontend.py"]
