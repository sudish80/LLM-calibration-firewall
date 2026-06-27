FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/dist/*.whl .
RUN pip install --no-cache-dir *.whl && rm *.whl

COPY --from=builder /build/src/llmfirewall/config.py /usr/local/lib/python3.11/site-packages/llmfirewall/config.py

RUN groupadd -r firewall && useradd -r -g firewall firewall
RUN mkdir -p /data/chromadb /data/models /data/logs && chown -R firewall:firewall /data

USER firewall

ENV LLMFW_CHROMADB_PERSIST_DIRECTORY=/data/chromadb
ENV LLMFW_MODEL_CACHE_DIR=/data/models
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

ENTRYPOINT ["llmfirewall"]
CMD ["server"]
