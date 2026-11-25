# Minimal, secure container image for self-hosting the SNOW Relay Service
FROM python:3.13-slim

WORKDIR /app

# Non-root user for security
RUN groupadd -r snow && useradd -r -g snow snow

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY src/ /app/src/

ENV PYTHONPATH="/app/src"
ENV SNOW_RELAY_HOST="0.0.0.0"

EXPOSE 8770

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; p = os.getenv('PORT') or os.getenv('SNOW_RELAY_PORT', '8770'); urllib.request.urlopen(f'http://127.0.0.1:{p}/health', timeout=3)" || exit 1

USER snow

ENTRYPOINT ["python", "-m", "snow.relay"]
