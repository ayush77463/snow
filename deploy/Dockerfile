# SNOW Remote MCP Gateway & Relay — Production Container
FROM python:3.13-slim AS base

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

# Install security updates and curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user
RUN groupadd -g 10001 snow && \
    useradd -u 10001 -g snow -m -s /bin/bash snow

# Copy packaging and source
COPY pyproject.toml .
COPY src/ ./src/

# Install application using pyproject.toml metadata
RUN pip install --no-cache-dir .

# Set up data directory with correct ownership
RUN mkdir -p /home/snow/.snow && \
    chown -R snow:snow /app /home/snow/.snow

USER snow:snow

EXPOSE 8771 8770

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8771/health || exit 1

ENTRYPOINT ["python", "-m", "snow.mcp.remote_gateway", "--host", "0.0.0.0", "--port", "8771"]
