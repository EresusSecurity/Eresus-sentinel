FROM python:3.11-slim

LABEL org.opencontainers.image.title="Eresus Sentinel"
LABEL org.opencontainers.image.description="Deterministic-first security platform for AI/LLM ecosystems"
LABEL org.opencontainers.image.source="https://github.com/EresusSecurity/Eresus-sentiel"

RUN pip install --no-cache-dir eresus-sentinel

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
