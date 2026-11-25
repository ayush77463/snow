# Minimal, secure container image for self-hosting the SNOW Relay Service (Render Free Tier)
FROM python:3.13-slim

WORKDIR /app

# Non-root user for security
RUN groupadd -r snow && useradd -r -g snow snow

# Install only the runtime dependencies genuinely required by snow.relay
RUN pip install --no-cache-dir \
    "aiohttp>=3.10.0" \
    "cryptography>=43.0.0"

# Copy only the minimal snow.relay package structure (no desktop modules, databases, or secrets)
RUN mkdir -p /app/src/snow/relay && chown -R snow:snow /app
COPY --chown=snow:snow src/snow/__init__.py /app/src/snow/__init__.py
COPY --chown=snow:snow src/snow/relay/ /app/src/snow/relay/

ENV PYTHONPATH="/app/src"
ENV SNOW_RELAY_HOST="0.0.0.0"
ENV SNOW_RELAY_ENABLED="1"

EXPOSE 8770

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; p = os.getenv('PORT') or os.getenv('SNOW_RELAY_PORT', '8770'); urllib.request.urlopen(f'http://127.0.0.1:{p}/health', timeout=3)" || exit 1

USER snow

ENTRYPOINT ["python", "-m", "snow.relay"]
